/**
 * Runtime settings changed from inside the app (slash commands), shared by the TUI and the server plugin.
 * Config options are the defaults; these override them without a restart.
 * The file is guardrail-protected: the agent can't change it from the shell or file tools.
 */
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join } from "node:path"

export type EffortMode = "suggest" | "auto" | "off"

export interface KomainuSettings {
  readonly effort?: EffortMode
  readonly spend?: { readonly show?: boolean; readonly daily?: number }
  /** Optional sponsor messages. enabled:false hides all of them; aiand records the one-time welcome's outcome. */
  readonly sponsors?: { readonly enabled?: boolean; readonly aiand?: SponsorState }
  /** Image guard for attached images (overrides the plugin option). */
  readonly images?: { readonly mode?: ImageGuardMode }
  /** Threat memory: remember flagged sources across sessions/projects (default on). */
  readonly memory?: { readonly enabled?: boolean }
}

export type ImageGuardMode = "ask" | "block" | "off"
const IMAGE_MODES: readonly string[] = ["ask", "block", "off"]
export type SponsorState = "dismissed" | "connected"
const SPONSOR_STATES: readonly string[] = ["dismissed", "connected"]
const bool = (v: unknown) => (typeof v === "boolean" ? v : undefined)

export const settingsDir = () => join(process.env.XDG_STATE_HOME || join(homedir(), ".local", "state"), "komainu")
export const settingsPath = () => join(settingsDir(), "settings.json")

const EFFORT_MODES: readonly string[] = ["suggest", "auto", "off"]

function sanitize(raw: unknown): KomainuSettings {
  if (!raw || typeof raw !== "object") return {}
  const r = raw as Record<string, any>
  const daily = Number(r.spend?.daily)
  return {
    ...(r.effort === "ask" ? { effort: "suggest" as const } : EFFORT_MODES.includes(r.effort) ? { effort: r.effort as EffortMode } : {}),
    ...(r.spend && typeof r.spend === "object"
      ? { spend: { ...(typeof r.spend.show === "boolean" ? { show: r.spend.show } : {}), ...(daily > 0 ? { daily } : {}) } }
      : {}),
    ...(r.sponsors && typeof r.sponsors === "object"
      ? {
          sponsors: {
            ...(bool(r.sponsors.enabled) === undefined ? {} : { enabled: r.sponsors.enabled as boolean }),
            ...(SPONSOR_STATES.includes(r.sponsors.aiand) ? { aiand: r.sponsors.aiand as SponsorState } : {}),
          },
        }
      : {}),
    ...(r.images && typeof r.images === "object" && IMAGE_MODES.includes(r.images.mode) ? { images: { mode: r.images.mode as ImageGuardMode } } : {}),
    ...(r.memory && typeof r.memory === "object" && bool(r.memory.enabled) !== undefined ? { memory: { enabled: r.memory.enabled as boolean } } : {}),
  }
}

export function readSettings(path = settingsPath()): KomainuSettings {
  try {
    return sanitize(JSON.parse(readFileSync(path, "utf8")))
  } catch {
    return {}
  }
}

export function writeSettings(update: (current: KomainuSettings) => KomainuSettings, path = settingsPath()): KomainuSettings {
  const next = sanitize(update(readSettings(path)))
  mkdirSync(dirname(path), { recursive: true })
  writeFileSync(path, JSON.stringify(next, null, 2) + "\n", { mode: 0o600 })
  return next
}

/** Returns a reader that re-parses the file only when it changes (cheap enough to call per request). */
export function cachedSettings(path = settingsPath()): () => KomainuSettings {
  let mtime = Number.NaN
  let value: KomainuSettings = {}
  return () => {
    let m = -1
    try {
      m = statSync(path).mtimeMs
    } catch {}
    if (m !== mtime) {
      mtime = m
      value = m < 0 ? {} : readSettings(path)
    }
    return value
  }
}
