/**
 * Optional integration credentials (currently: Neo4j). Kept out of opencode.json and out of the environment,
 * so the agent's shell never inherits them. The file name matches the secret-file rules, so the policy engine
 * and the OS sandbox both refuse agent reads of it.
 */
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { settingsDir } from "./settings.js"

export interface Neo4jCredentials {
  readonly uri: string
  readonly user: string
  readonly password: string
  readonly database?: string
}

export const credentialsPath = () => join(settingsDir(), "credentials.json")

const NEO4J_SCHEMES = /^(?:neo4j|neo4j\+s|neo4j\+ssc|bolt|bolt\+s|bolt\+ssc):\/\/[^\s]+$/

export function validNeo4jUri(uri: string) {
  return NEO4J_SCHEMES.test(uri.trim())
}

export function readNeo4jCredentials(path = credentialsPath()): Neo4jCredentials | undefined {
  try {
    const n = JSON.parse(readFileSync(path, "utf8"))?.neo4j
    if (!n || typeof n.uri !== "string" || !validNeo4jUri(n.uri) || typeof n.password !== "string") return undefined
    return { uri: n.uri.trim(), user: typeof n.user === "string" && n.user ? n.user : "neo4j", password: n.password, ...(typeof n.database === "string" && n.database ? { database: n.database } : {}) }
  } catch {
    return undefined
  }
}

export function writeNeo4jCredentials(creds: Neo4jCredentials | undefined, path = credentialsPath()) {
  let rest: Record<string, unknown> = {}
  try {
    rest = JSON.parse(readFileSync(path, "utf8")) ?? {}
  } catch {}
  const next = { ...rest, neo4j: creds }
  if (!creds) delete next.neo4j
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(next, null, 2) + "\n", { mode: 0o600 })
}

/** Re-reads only when the file changes. */
export function cachedNeo4jCredentials(path = credentialsPath()): () => Neo4jCredentials | undefined {
  let mtime = Number.NaN
  let value: Neo4jCredentials | undefined
  return () => {
    let m = -1
    try {
      m = statSync(path).mtimeMs
    } catch {}
    if (m !== mtime) {
      mtime = m
      value = m < 0 ? undefined : readNeo4jCredentials(path)
    }
    return value
  }
}

/** Parses the credentials .txt that Neo4j Aura offers for download (NEO4J_URI=…, NEO4J_USERNAME=…, NEO4J_PASSWORD=…). */
export function parseAuraCredentials(text: string): Neo4jCredentials | undefined {
  const env: Record<string, string> = {}
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line)
    if (m) env[m[1]!] = m[2]!.replace(/^["']|["']$/g, "")
  }
  const uri = env.NEO4J_URI
  const password = env.NEO4J_PASSWORD
  if (!uri || !password || !validNeo4jUri(uri)) return undefined
  return { uri, user: env.NEO4J_USERNAME || env.NEO4J_USER || "neo4j", password, ...(env.NEO4J_DATABASE ? { database: env.NEO4J_DATABASE } : {}) }
}
