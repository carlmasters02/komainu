/**
 * Turns findings into allow / ask / deny, taking session taint and the user's chosen mode into account.
 */
import { homedir, tmpdir } from "node:os"
import { isAbsolute, normalize, relative, resolve } from "node:path"
import { containsSecret, isSensitivePath } from "./secrets.js"
import { analyzeShell, shellWriteTargets } from "./shell.js"
import { describe, strongest, type Decision, type Effect, type Finding, type Severity } from "./types.js"

export type Mode = "strict" | "balanced" | "permissive"

export interface PolicyConfig {
  readonly mode: Mode
  readonly workspace: string
  /** Paths (relative to workspace, or ~/absolute) that hold the harness's own guardrails. */
  readonly protectedPaths: readonly string[]
}

export interface PolicyContext {
  readonly tainted: boolean
}

export const DEFAULT_PROTECTED = ["opencode.json", "opencode.jsonc", ".opencode/", ".komainu/", "komainu.json", ".git/hooks/", ".git/config", "~/.config/opencode/", "~/.config/komainu/", "~/.local/state/komainu/"]

/** Rules that are harmless on their own but are exactly what an injected prompt would want. */
const TAINT_ESCALATE = new Set(["network-egress", "package-install", "custom-registry", "git-push", "git-remote-add", "network-upload", "env-dump", "url-query-data", "write-outside-workspace", "ci-config-write"])

function effectFor(sev: Severity, rule: string, mode: Mode, ctx: PolicyContext): Effect {
  if (sev === "critical") return "deny"
  if (sev === "high") return mode === "permissive" && !ctx.tainted ? "allow" : "ask"
  if (sev === "medium") return mode === "strict" || ctx.tainted ? "ask" : "allow"
  if (sev === "low") return ctx.tainted && TAINT_ESCALATE.has(rule) ? "ask" : "allow"
  return "allow"
}

export function decide(findings: readonly Finding[], cfg: PolicyConfig, ctx: PolicyContext): Decision {
  let effect: Effect = "allow"
  for (const f of findings) effect = strongest(effect, effectFor(f.severity, f.rule, cfg.mode, ctx))
  const relevant = findings.filter((f) => f.severity !== "info")
  const taintNote = ctx.tainted && effect !== "allow" ? "\n(This session has read untrusted external content, so risky actions require confirmation.)" : ""
  return { effect, findings, reason: relevant.length ? describe(relevant) + taintNote : undefined }
}

export function decideShell(command: string, cfg: PolicyConfig, ctx: PolicyContext): Decision {
  const findings = analyzeShell(command)
  // Shell writes get the same checks as the write tool (protected guardrail files, secrets, CI config).
  for (const target of shellWriteTargets(command)) {
    const path = target.replace(/^\$\{?HOME\}?(?=\/|$)/, homedir())
    const abs = resolvePath(path, cfg.workspace)
    if (!inside(abs, cfg.workspace) && [tmpdir(), "/tmp", "/var/tmp"].some((t) => inside(abs, t))) continue
    for (const finding of decideFileAccess("write", path, cfg, ctx).findings)
      if (!findings.some((x) => x.rule === finding.rule)) findings.push({ ...finding, message: `${finding.message} (via shell)` })
  }
  return decide(findings, cfg, ctx)
}

export function resolvePath(p: string, workspace: string): string {
  const expanded = p.startsWith("~") ? p.replace(/^~/, homedir()) : p
  return normalize(isAbsolute(expanded) ? expanded : resolve(workspace, expanded))
}

const inside = (child: string, parent: string) => {
  const rel = relative(parent, child)
  return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel))
}

export function isProtected(abs: string, cfg: PolicyConfig): boolean {
  return cfg.protectedPaths.some((p) => {
    const target = resolvePath(p.replace(/\/$/, ""), cfg.workspace)
    return p.endsWith("/") ? inside(abs, target) : abs === target
  })
}

export function decideFileAccess(kind: "read" | "write", path: string, cfg: PolicyConfig, ctx: PolicyContext): Decision {
  const abs = resolvePath(path, cfg.workspace)
  const findings: Finding[] = []
  if (isSensitivePath(abs))
    findings.push({ rule: kind === "read" ? "sensitive-read" : "sensitive-write", severity: cfg.mode === "strict" ? "critical" : "high", message: `${kind} of credential/secret file ${path}` })
  if (kind === "write") {
    if (isProtected(abs, cfg))
      findings.push({ rule: "guardrail-tamper", severity: cfg.mode === "strict" ? "critical" : "high", message: `Modifies the agent's own security configuration or git hooks: ${path}` })
    if (!inside(abs, cfg.workspace)) findings.push({ rule: "write-outside-workspace", severity: "medium", message: `Writes outside the project: ${abs}` })
    if (/[\\/]\.github[\\/]workflows[\\/]|\.gitlab-ci\.ya?ml$|[\\/]\.circleci[\\/]/.test(abs))
      findings.push({ rule: "ci-config-write", severity: "low", message: `Modifies CI pipeline config: ${path}` })
  } else if (!inside(abs, cfg.workspace) && !abs.startsWith("/tmp")) {
    findings.push({ rule: "read-outside-workspace", severity: "low", message: `Reads outside the project: ${abs}` })
  }
  return decide(findings, cfg, ctx)
}

const PRIVATE_HOST = /^(?:localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|\[?::1\]?|metadata\.google\.internal|[^.]+\.internal$)/i

export function decideFetch(url: string, cfg: PolicyConfig, ctx: PolicyContext): Decision {
  const findings: Finding[] = []
  let u: URL | undefined
  try {
    u = new URL(url)
  } catch {
    findings.push({ rule: "bad-url", severity: "medium", message: `Unparseable URL: ${url}` })
  }
  if (u) {
    if (u.hostname === "169.254.169.254" || u.hostname === "metadata.google.internal")
      findings.push({ rule: "cloud-metadata", severity: "critical", message: "Requests cloud instance metadata (credential theft vector)" })
    else if (PRIVATE_HOST.test(u.hostname)) findings.push({ rule: "private-network", severity: "medium", message: `Requests a private/internal address: ${u.hostname}` })
    if (u.protocol !== "https:" && u.protocol !== "http:") findings.push({ rule: "url-scheme", severity: "high", message: `Non-HTTP scheme: ${u.protocol}` })
    if (containsSecret(url)) findings.push({ rule: "secret-in-url", severity: "critical", message: "URL contains what looks like a credential (exfiltration)" })
    else if (u.search.length > 200 || /[A-Za-z0-9+/=_-]{120,}/.test(u.pathname + u.search))
      findings.push({ rule: "url-query-data", severity: "low", message: "URL carries a large encoded payload" })
  }
  return decide(findings, cfg, ctx)
}

