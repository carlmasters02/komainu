/**
 * Tamper-evident audit log: append-only JSONL where each entry commits to the previous one's hash.
 * Editing or deleting any line breaks the chain from that point on, which `verifyAuditLog` reports.
 * All payloads are secret-redacted before they touch disk.
 */
import { createHash } from "node:crypto"
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs"
import { dirname } from "node:path"
import { redactDeep } from "./secrets.js"

export interface AuditEvent {
  readonly kind: string
  readonly sessionID?: string
  readonly tool?: string
  readonly effect?: string
  readonly [key: string]: unknown
}

export interface AuditEntry {
  readonly seq: number
  readonly ts: string
  readonly prev: string
  readonly event: AuditEvent
  readonly hash: string
}

const GENESIS = "0".repeat(64)
const digest = (prev: string, seq: number, ts: string, event: AuditEvent) =>
  createHash("sha256").update(`${prev}\n${seq}\n${ts}\n${JSON.stringify(event)}`).digest("hex")

export class AuditLog {
  private seq = 0
  private prev = GENESIS

  constructor(readonly path: string) {
    mkdirSync(dirname(path), { recursive: true })
    if (existsSync(path)) {
      const lines = readFileSync(path, "utf8").trimEnd().split("\n").filter(Boolean)
      const last = lines.at(-1)
      if (last) {
        const entry = JSON.parse(last) as AuditEntry
        this.seq = entry.seq + 1
        this.prev = entry.hash
      }
    }
  }

  append(event: AuditEvent): AuditEntry {
    const clean = redactDeep(event)
    const ts = new Date().toISOString()
    const hash = digest(this.prev, this.seq, ts, clean)
    const entry: AuditEntry = { seq: this.seq, ts, prev: this.prev, event: clean, hash }
    appendFileSync(this.path, JSON.stringify(entry) + "\n", { mode: 0o600 })
    this.seq++
    this.prev = hash
    return entry
  }
}

export function verifyAuditLog(path: string): { ok: true; entries: number } | { ok: false; brokenAt: number; reason: string } {
  const lines = readFileSync(path, "utf8").trimEnd().split("\n").filter(Boolean)
  let prev = GENESIS
  for (const [i, line] of lines.entries()) {
    let e: AuditEntry
    try {
      e = JSON.parse(line)
    } catch {
      return { ok: false, brokenAt: i, reason: "unparseable line" }
    }
    if (e.seq !== i) return { ok: false, brokenAt: i, reason: `sequence gap (expected ${i}, got ${e.seq})` }
    if (e.prev !== prev) return { ok: false, brokenAt: i, reason: "prev-hash mismatch" }
    if (digest(e.prev, e.seq, e.ts, e.event) !== e.hash) return { ok: false, brokenAt: i, reason: "content hash mismatch" }
    prev = e.hash
  }
  return { ok: true, entries: lines.length }
}
