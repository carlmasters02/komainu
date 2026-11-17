/**
 * Optional Neo4j sink + recall. Off unless credentials exist (/komainu → Neo4j).
 *
 *   write: every audit entry → (:Event) linked to (:Project) (:Session) (:Source) (:Layer) (:Target), chained by [:NEXT]
 *   read:  "has this source / domain misbehaved before?" across every project (and teammate) writing to the same DB
 *
 * Never on the critical path: writes are batched and fire-and-forget, reads time out fast, failures go quiet.
 * Only already-redacted audit fields are sent; file contents never are.
 */
import { classify, type AuditEntry, type Incident, type Neo4jCredentials } from "@komainu/core"

type Driver = {
  session(opts?: { database?: string; defaultAccessMode?: string }): {
    run(query: string, params?: Record<string, unknown>): Promise<{ records: Array<{ get(key: string): unknown }> }>
    close(): Promise<void>
  }
  close(): Promise<void>
}
export type DriverModule = { driver(uri: string, auth: unknown, config?: Record<string, unknown>): Driver; auth: { basic(user: string, password: string): unknown } }

export interface GraphSink {
  push(entry: AuditEntry): void
  recall(key: string): Promise<Incident | undefined>
  flush(): Promise<void>
  status(): { connected: boolean; uri?: string; error?: string; sent: number }
  close(): Promise<void>
}

const SCHEMA = [
  "CREATE CONSTRAINT komainu_event IF NOT EXISTS FOR (e:Event) REQUIRE e.hash IS UNIQUE",
  "CREATE CONSTRAINT komainu_project IF NOT EXISTS FOR (p:Project) REQUIRE p.path IS UNIQUE",
  "CREATE CONSTRAINT komainu_session IF NOT EXISTS FOR (s:Session) REQUIRE s.id IS UNIQUE",
  "CREATE CONSTRAINT komainu_source IF NOT EXISTS FOR (s:Source) REQUIRE s.key IS UNIQUE",
  "CREATE CONSTRAINT komainu_layer IF NOT EXISTS FOR (l:Layer) REQUIRE l.name IS UNIQUE",
  "CREATE CONSTRAINT komainu_target IF NOT EXISTS FOR (t:Target) REQUIRE t.host IS UNIQUE",
]

export const WRITE_QUERY = `
UNWIND $rows AS r
MERGE (p:Project {path: r.project})
MERGE (e:Event {hash: r.hash})
  SET e.seq = r.seq, e.ts = datetime(r.ts), e.kind = r.kind, e.action = r.action, e.outcome = r.outcome,
      e.severity = r.severity, e.detail = r.detail, e.rules = r.rules
MERGE (e)-[:IN_PROJECT]->(p)
MERGE (l:Layer {name: r.layer})
MERGE (e)-[:CAUGHT_BY]->(l)
FOREACH (ignored IN CASE WHEN r.session IS NULL THEN [] ELSE [1] END |
  MERGE (s:Session {id: r.session}) MERGE (s)-[:IN]->(p) MERGE (e)-[:IN_SESSION]->(s))
FOREACH (ignored IN CASE WHEN r.source IS NULL THEN [] ELSE [1] END |
  MERGE (src:Source {key: r.source}) MERGE (e)-[:FROM]->(src))
FOREACH (t IN r.targets | MERGE (x:Target {host: t}) MERGE (e)-[:TOUCHED]->(x))
WITH e, r
OPTIONAL MATCH (prev:Event {hash: r.prev})
FOREACH (ignored IN CASE WHEN prev IS NULL THEN [] ELSE [1] END | MERGE (prev)-[:NEXT]->(e))`

const RECALL_SOURCE = `
MATCH (:Source {key: $key})<-[:FROM]-(e:Event {kind: 'taint', severity: 'bad'})-[:IN_PROJECT]->(p:Project)
RETURN count(e) AS count, toString(min(e.ts)) AS first, toString(max(e.ts)) AS last,
       collect(DISTINCT p.path)[..10] AS projects, collect(e.rules) AS rules`

const RECALL_DOMAIN = `
MATCH (:Target {host: $key})<-[:TOUCHED]-(e:Event)-[:IN_PROJECT]->(p:Project)
WHERE e.outcome IN ['blocked', 'you denied']
RETURN count(e) AS count, toString(min(e.ts)) AS first, toString(max(e.ts)) AS last,
       collect(DISTINCT p.path)[..10] AS projects, collect([e.outcome]) AS rules`

/** Audit entry → row for WRITE_QUERY (undefined for bookkeeping entries). */
export function toRow(entry: AuditEntry, project: string) {
  const step = classify(entry)
  if (!step) return undefined
  const src = step.source
  const source = !src ? null : src.startsWith("web: ") ? `url:${src.slice(5)}` : src.startsWith("tool: ") ? `tool:${src.slice(6)}` : src.startsWith("memory: ") ? src.slice(8) : src.startsWith("image: ") ? `image:${String((entry.event as Record<string, unknown>).sha256 ?? "")}` : null
  const ev = entry.event as Record<string, unknown>
  const rules = [ev.suspicious, ev.findings].flatMap((v) => (Array.isArray(v) ? v.map(String) : []))
  return {
    project, hash: entry.hash, prev: entry.prev, seq: entry.seq, ts: entry.ts, kind: step.kind, action: step.action,
    outcome: step.outcome, severity: step.severity, detail: step.detail, layer: step.layer, rules,
    session: step.sessionID ?? null, source, targets: [...step.targets],
  }
}

const num = (v: unknown) => (typeof v === "number" ? v : typeof (v as { toNumber?: () => number })?.toNumber === "function" ? (v as { toNumber(): number }).toNumber() : Number(v))

export function createNeo4jSink(
  creds: () => Neo4jCredentials | undefined,
  project: string,
  opts: { load?: () => Promise<DriverModule>; flushMs?: number; recallTimeoutMs?: number } = {},
): GraphSink {
  const load = opts.load ?? (async () => ((await import("neo4j-driver")) as unknown as { default: DriverModule }).default)
  let driver: Driver | undefined
  let driverKey = ""
  let ready: Promise<Driver | undefined> | undefined
  let error: string | undefined
  let sent = 0
  let queue: NonNullable<ReturnType<typeof toRow>>[] = []
  let lastHash: string | null = null // chain only the events we send (bookkeeping entries are skipped)
  let timer: ReturnType<typeof setTimeout> | undefined
  const cache = new Map<string, { at: number; value: Incident | undefined }>()

  const connect = (): Promise<Driver | undefined> => {
    const c = creds()
    const key = c ? `${c.uri}|${c.user}|${c.password}|${c.database ?? ""}` : ""
    if (!c) {
      if (driver) void driver.close().catch(() => undefined)
      driver = undefined
      driverKey = ""
      ready = undefined
      return Promise.resolve(undefined)
    }
    if (ready && key === driverKey) return ready
    if (driver) void driver.close().catch(() => undefined)
    driverKey = key
    ready = (async () => {
      try {
        const mod = await load()
        const d = mod.driver(c.uri, mod.auth.basic(c.user, c.password), { connectionTimeout: 5000, maxTransactionRetryTime: 5000, userAgent: "komainu" })
        const s = d.session({ database: c.database })
        try {
          for (const q of SCHEMA) await s.run(q)
        } finally {
          await s.close()
        }
        driver = d
        error = undefined
        return d
      } catch (e) {
        error = String((e as Error)?.message ?? e).split("\n")[0]
        driver = undefined
        return undefined
      }
    })()
    return ready
  }

  const flush = async () => {
    timer = undefined
    if (!queue.length) return
    const d = await connect()
    if (!d) {
      if (!creds()) queue = []
      else queue = queue.slice(-5000) // keep a bounded backlog while the DB is unreachable
      return
    }
    const rows = queue
    queue = []
    const s = d.session({ database: creds()?.database })
    try {
      await s.run(WRITE_QUERY, { rows })
      sent += rows.length
      cache.clear()
    } catch (e) {
      error = String((e as Error)?.message ?? e).split("\n")[0]
      queue = [...rows, ...queue].slice(-5000)
      ready = undefined // reconnect next time
    } finally {
      await s.close().catch(() => undefined)
    }
  }

  const recall = async (key: string): Promise<Incident | undefined> => {
    if (!creds()) return undefined
    const hit = cache.get(key)
    if (hit && Date.now() - hit.at < 60_000) return hit.value
    const kind = key.slice(0, key.indexOf(":")) as Incident["kind"]
    const run = (async () => {
      const d = await connect()
      if (!d) return undefined
      const s = d.session({ database: creds()?.database, defaultAccessMode: "READ" })
      try {
        const res = await s.run(kind === "domain" ? RECALL_DOMAIN : RECALL_SOURCE, { key: kind === "domain" ? key.slice(7) : key })
        const r = res.records[0]
        const count = r ? num(r.get("count")) : 0
        if (!r || !count) return undefined
        const rules = ([] as unknown[]).concat(...((r.get("rules") as unknown[][]) ?? [])).map(String)
        return {
          key, kind, count, reasons: [...new Set(rules)].slice(0, 10), first: String(r.get("first") ?? ""), last: String(r.get("last") ?? ""),
          projects: ((r.get("projects") as unknown[]) ?? []).map(String),
        } satisfies Incident
      } finally {
        await s.close().catch(() => undefined)
      }
    })()
    const value = await Promise.race([run.catch(() => undefined), new Promise<undefined>((r) => setTimeout(() => r(undefined), opts.recallTimeoutMs ?? 1500))])
    cache.set(key, { at: Date.now(), value })
    return value
  }

  return {
    push(entry) {
      if (!creds()) return
      const row = toRow(entry, project)
      if (!row) return
      queue.push({ ...row, prev: lastHash ?? "" })
      lastHash = row.hash
      timer ??= setTimeout(() => void flush(), opts.flushMs ?? 1000)
    },
    recall,
    flush: async () => {
      if (timer) clearTimeout(timer)
      await flush()
    },
    status: () => ({ connected: !!driver, uri: creds()?.uri, error, sent }),
    close: async () => {
      if (timer) clearTimeout(timer)
      await flush().catch(() => undefined)
      await driver?.close().catch(() => undefined)
    },
  }
}

/** Shared Cypher snippets shown in the UI / docs. */
export const EXAMPLE_QUERIES = {
  attackPaths: "MATCH path = (:Source)<-[:FROM]-(:Event)-[:IN_SESSION]->(:Session)<-[:IN_SESSION]-(e:Event)-[:CAUGHT_BY]->(:Layer) WHERE e.outcome IN ['blocked','you denied'] RETURN path LIMIT 25",
  flaggedSources: "MATCH (s:Source)<-[:FROM]-(e:Event {severity:'bad'})-[:IN_PROJECT]->(p:Project) RETURN s.key, count(e) AS incidents, collect(DISTINCT p.path) AS projects ORDER BY incidents DESC",
  layers: "MATCH (e:Event)-[:CAUGHT_BY]->(l:Layer) WHERE e.severity <> 'ok' RETURN l.name, e.outcome, count(*) ORDER BY count(*) DESC",
}
