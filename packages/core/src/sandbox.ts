/**
 * OS-level isolation via Anthropic's open-source sandbox-runtime (`srt`, Apache-2.0):
 * bubblewrap on Linux, Seatbelt on macOS, network forced through a filtering proxy.
 * This is the actual security boundary; everything else in Komainu is defence in depth.
 * fork/install.sh sets srt up (installed with Bun and run on Bun when Node.js is missing or too old);
 * Linux also needs bubblewrap, socat and ripgrep.
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs"
import { homedir } from "node:os"
import { dirname, join } from "node:path"
import { SENSITIVE_DENY_READ_GLOBS } from "./secrets.js"

export interface SandboxConfig {
  readonly workspace: string
  /** Extra writable roots besides the workspace (e.g. a cache dir). */
  readonly allowWrite?: readonly string[]
  readonly allowedDomains?: readonly string[]
  readonly extraDenyRead?: readonly string[]
  /** Paths inside the workspace the agent must not modify from the shell (its own guardrails, git hooks). */
  readonly denyWrite?: readonly string[]
}

export const DEFAULT_ALLOWED_DOMAINS = [
  "registry.npmjs.org", "registry.yarnpkg.com", "bun.sh",
  "pypi.org", "files.pythonhosted.org",
  "crates.io", "static.crates.io", "index.crates.io",
  "proxy.golang.org", "sum.golang.org",
  "github.com", "codeload.github.com", "objects.githubusercontent.com", "raw.githubusercontent.com",
]

export const DEFAULT_DENY_WRITE = [
  ".git/hooks", ".git/config",
  "opencode.json", "opencode.jsonc", ".opencode",
  ".komainu", "komainu.json",
  "~/.config/opencode", "~/.config/komainu", "~/.local/state/komainu", "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile",
]

/**
 * Finds srt. install.sh puts its own srt next to the komainu binary only when the one on PATH is missing or
 * broken, so that copy comes first; then PATH; then ~/.local/bin, for when that folder isn't on PATH yet.
 */
export function srtBinary(execPath = process.execPath, home = homedir()): string | undefined {
  const besideKomainu = join(dirname(execPath), "srt")
  if (existsSync(besideKomainu)) return besideKomainu
  const onPath = Bun.which("srt")
  if (onPath) return onPath
  const local = join(home, ".local", "bin", "srt")
  return existsSync(local) ? local : undefined
}

export function buildSrtSettings(cfg: SandboxConfig) {
  return {
    filesystem: {
      denyRead: [...SENSITIVE_DENY_READ_GLOBS, ...(cfg.extraDenyRead ?? [])],
      allowWrite: [cfg.workspace, "/tmp", ...(cfg.allowWrite ?? [])],
      denyWrite: (cfg.denyWrite ?? DEFAULT_DENY_WRITE).map((p) => (p.startsWith("/") || p.startsWith("~") ? p : join(cfg.workspace, p))),
    },
    network: {
      allowedDomains: [...(cfg.allowedDomains ?? DEFAULT_ALLOWED_DOMAINS)],
      deniedDomains: [],
    },
  }
}

export function writeSrtSettings(cfg: SandboxConfig, dir: string): string {
  mkdirSync(dir, { recursive: true })
  const path = join(dir, "srt-settings.json")
  writeFileSync(path, JSON.stringify(buildSrtSettings(cfg), null, 2), { mode: 0o600 })
  return path
}

export const shellQuote = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`

/** Rewrites a shell command string so it executes inside srt. */
export function wrapCommand(command: string, settingsPath: string, srt = "srt"): string {
  return `${shellQuote(srt)} --settings ${shellQuote(settingsPath)} -c ${shellQuote(command)}`
}

export const isWrapped = (command: string, srt = "srt") => command.startsWith(shellQuote(srt) + " --settings ")
