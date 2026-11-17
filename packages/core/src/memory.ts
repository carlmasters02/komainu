/**
 * Threat memory: what Komainu has seen misbehave, remembered across sessions and projects.
 *
 *   url:<host>     a web source whose content matched prompt-injection heuristics
 *   tool:<name>    an MCP/plugin tool whose output matched them
 *   domain:<host>  a network destination that was blocked by policy or denied by you
 *
 * Recall can only make Komainu stricter (allow → ask). A poisoned memory can't grant anything.
 * Stored next to the runtime settings (guardrail-protected), so the agent can't edit it.
 */
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { settingsDir } from "./settings.js"

export type IncidentKind = "url" | "tool" | "domain"

export interface Incident {
  readonly key: string
  readonly kind: IncidentKind
  readonly reasons: readonly string[]
  readonly count: number
  readonly first: string
  readonly last: string
  readonly projects: readonly string[]
}

export const memoryPath = () => join(settingsDir(), "threat-memory.json")

const MAX_ENTRIES = 2000
const MAX_LIST = 10

/**
 * Hosts where anyone can publish: flagging the whole host would flag everyone on it, so memory is scoped to the
 * account (and for package registries, the package). Value = how many path segments identify the publisher.
 */
const MULTI_TENANT: Readonly<Record<string, number>> = {
  "github.com": 1, "raw.githubusercontent.com": 1, "gist.github.com": 1, "gist.githubusercontent.com": 1, "objects.githubusercontent.com": 1,
  "gitlab.com": 1, "bitbucket.org": 1, "codeberg.org": 1, "huggingface.co": 1, "pastebin.com": 1, "medium.com": 1, "dev.to": 1,
  "www.npmjs.com": 2, "npmjs.com": 2, "pypi.org": 2, "crates.io": 2, "pkg.go.dev": 1, "docs.google.com": 3, "drive.google.com": 3,
}

export const isMultiTenantHost = (host: string) => host in MULTI_TENANT

/** What a remembered web source is: the host, or host/publisher on shared hosts (github.com/attacker). */
export function sourceScope(url: string): string | undefined {
  const host = hostOf(url)
  if (!host) return undefined
  const depth = MULTI_TENANT[host]
  if (!depth) return host
  const segs = new URL(url).pathname.split("/").filter(Boolean).slice(0, depth)
  return segs.length ? `${host}/${segs.join("/").toLowerCase()}` : host
}

export const sourceKey = (tool: string, detail: string): string | undefined => {
  if (tool === "websearch") return undefined // a query isn't a source
  const scope = sourceScope(detail)
  if (scope) return `url:${scope}`
  return tool === "webfetch" ? undefined : `tool:${tool}`
}

export function hostOf(url: string): string | undefined {
  try {
    const u = new URL(url)
    return u.protocol === "http:" || u.protocol === "https:" ? u.hostname.toLowerCase() : undefined
  } catch {
    return undefined
  }
}

/** Hosts in http(s) URLs inside a shell command. URL-only on purpose: no guessing from bare words. */
/** Hosts in http(s) URLs inside a shell command, minus shared hosts (denying one URL on github.com shouldn't taint all of it). */
export function rememberableHosts(command: string): string[] {
  return commandHosts(command).filter((h) => !isMultiTenantHost(h))
}

export function commandHosts(command: string): string[] {
  const hosts = new Set<string>()
  for (const m of command.matchAll(/\bhttps?:\/\/[^\s'"`<>|;)]+/gi)) {
    const h = hostOf(m[0])
    if (h) hosts.add(h)
  }
  return [...hosts]
}

const uniq = (xs: readonly string[], add: readonly string[]) => [...new Set([...xs, ...add])].slice(-MAX_LIST)

export class ThreatMemory {
  private mtime = Number.NaN
  private entries = new Map<string, Incident>()

  constructor(readonly path = memoryPath()) {}

  private load() {
    let m = -1
    try {
      m = statSync(this.path).mtimeMs
    } catch {}
    if (m === this.mtime) return
    this.mtime = m
    this.entries = new Map()
    if (m < 0) return
    try {
      const raw = JSON.parse(readFileSync(this.path, "utf8"))
      for (const i of Array.isArray(raw?.incidents) ? raw.incidents : []) {
        if (typeof i?.key === "string" && ["url", "tool", "domain"].includes(i.kind)) this.entries.set(i.key, i as Incident)
      }
    } catch {}
  }

  private save() {
    const incidents = [...this.entries.values()].sort((a, b) => a.last.localeCompare(b.last)).slice(-MAX_ENTRIES)
    mkdirSync(dirname(this.path), { recursive: true })
    writeFileSync(this.path, JSON.stringify({ version: 1, incidents }, null, 1) + "\n", { mode: 0o600 })
    try {
      this.mtime = statSync(this.path).mtimeMs
    } catch {}
  }

  record(key: string, reasons: readonly string[], project: string, now = new Date()): Incident {
    this.load()
    const kind = key.slice(0, key.indexOf(":")) as IncidentKind
    const prev = this.entries.get(key)
    const ts = now.toISOString()
    const next: Incident = prev
      ? { ...prev, reasons: uniq(prev.reasons, reasons), count: prev.count + 1, last: ts, projects: uniq(prev.projects, [project]) }
      : { key, kind, reasons: uniq([], reasons), count: 1, first: ts, last: ts, projects: [project] }
    this.entries.set(key, next)
    this.save()
    return next
  }

  lookup(key: string): Incident | undefined {
    this.load()
    return this.entries.get(key)
  }

  list(): Incident[] {
    this.load()
    return [...this.entries.values()].sort((a, b) => b.last.localeCompare(a.last))
  }

  forget(key?: string) {
    this.load()
    if (key) this.entries.delete(key)
    else this.entries.clear()
    this.save()
  }
}

export function describeIncident(i: Incident, project?: string): string {
  const others = project ? i.projects.filter((p) => p !== project).length : 0
  const where = others === 1 ? ", in another project" : others > 1 ? `, in ${others} other projects` : ""
  const what = i.kind === "domain" ? "blocked or denied" : "flagged for prompt injection"
  return `${i.key.slice(i.key.indexOf(":") + 1)} was ${what} ${i.count}× before (last ${i.last.slice(0, 10)}${where}; ${i.reasons.join(", ")})`
}
