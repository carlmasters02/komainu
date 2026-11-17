/**
 * Secret detection and redaction, plus sensitive-path matching.
 * Patterns favour precision: a false negative here is backstopped by the sandbox's denyRead,
 * while a false positive corrupts tool output the model needs.
 */

export interface SecretPattern {
  readonly id: string
  readonly regex: RegExp
  /** Capture group holding the secret itself; 0 = whole match. */
  readonly group?: number
}

export const SECRET_PATTERNS: readonly SecretPattern[] = [
  { id: "private-key", regex: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z ]+ )?PRIVATE KEY-----/g },
  { id: "aws-access-key", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: "github-token", regex: /\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g },
  { id: "anthropic-key", regex: /\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g },
  { id: "openai-key", regex: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}\b/g },
  { id: "google-api-key", regex: /\bAIza[0-9A-Za-z_\-]{35}\b/g },
  { id: "slack-token", regex: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g },
  { id: "stripe-key", regex: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b/g },
  { id: "npm-token", regex: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: "hf-token", regex: /\bhf_[A-Za-z0-9]{30,}\b/g },
  { id: "jwt", regex: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { id: "url-credentials", regex: /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]{3,})@/gi, group: 1 },
  {
    id: "generic-assignment",
    regex:
      /\b[A-Za-z0-9_]*(?:api[_-]?key|secret|token|passwd|password|auth[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z0-9_]*\s*[:=]\s*["']?([A-Za-z0-9/+_\-.=]{12,})["']?/gi,
    group: 1,
  },
]

const PLACEHOLDER = /^(?:x+|\*+|<[^>]+>|\$\{?[A-Z_]+\}?|changeme|your[_-].*|example.*|placeholder|redacted.*|process\.env.*|os\.environ.*)$/i

export interface RedactionResult {
  readonly text: string
  readonly redactions: ReadonlyArray<{ readonly id: string; readonly count: number }>
}

export function redact(text: string, patterns: readonly SecretPattern[] = SECRET_PATTERNS): RedactionResult {
  const counts = new Map<string, number>()
  let out = text
  for (const p of patterns) {
    out = out.replace(p.regex, (match, ...groups) => {
      const secret = p.group ? (groups[p.group - 1] as string | undefined) : match
      if (!secret || PLACEHOLDER.test(secret) || secret.startsWith("[REDACTED")) return match
      counts.set(p.id, (counts.get(p.id) ?? 0) + 1)
      const tag = `[REDACTED:${p.id}]`
      return p.group ? match.replace(secret, tag) : tag
    })
  }
  return { text: out, redactions: [...counts].map(([id, count]) => ({ id, count })) }
}

export const containsSecret = (text: string) => redact(text).redactions.length > 0

/** Deep-redacts strings inside arbitrary JSON-like values (tool inputs/outputs, audit events). */
export function redactDeep<T>(value: T): T {
  if (typeof value === "string") return redact(value).text as T
  if (Array.isArray(value)) return value.map(redactDeep) as T
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(value)) out[k] = redactDeep(v)
    return out as T
  }
  return value
}

// ---------------------------------------------------------------- sensitive paths

const SENSITIVE_BASENAMES = [
  /^\.env$/,
  /^\.env\.(?!example$|sample$|template$|dist$|defaults$)[\w.-]+$/,
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?:_sk)?$/,
  /\.(?:pem|key|p12|pfx|jks|keystore|ppk|kdbx)$/,
  /^\.(?:npmrc|pypirc|netrc|pgpass|git-credentials|htpasswd)$/,
  /^credentials(?:\.json)?$/,
  /^(?:secrets?|service[-_]account)[\w.-]*\.(?:json|ya?ml|toml)$/,
  /^terraform\.tfstate(?:\.backup)?$/,
]

const SENSITIVE_SEGMENTS = [
  /(?:^|\/)\.ssh\//,
  /(?:^|\/)\.gnupg\//,
  /(?:^|\/)\.aws\//,
  /(?:^|\/)\.azure\//,
  /(?:^|\/)\.config\/gcloud\//,
  /(?:^|\/)\.kube\/config$/,
  /(?:^|\/)\.docker\/config\.json$/,
  /(?:^|\/)\.config\/gh\/hosts\.yml$/,
  /(?:^|\/)Library\/Keychains\//,
  /^\/etc\/(?:shadow|gshadow|sudoers)/,
]

export function isSensitivePath(path: string): boolean {
  const p = path.replace(/\\/g, "/").replace(/^["']|["']$/g, "")
  const base = p.split("/").pop() ?? p
  return SENSITIVE_BASENAMES.some((r) => r.test(base)) || SENSITIVE_SEGMENTS.some((r) => r.test(p))
}

/** Globs handed to the OS sandbox so the same paths are unreadable from inside shell commands. */
export const SENSITIVE_DENY_READ_GLOBS = [
  "~/.ssh",
  "~/.gnupg",
  "~/.aws",
  "~/.azure",
  "~/.config/gcloud",
  "~/.kube",
  "~/.docker/config.json",
  "~/.config/gh",
  "~/.npmrc",
  "~/.pypirc",
  "~/.netrc",
  "~/.git-credentials",
  "~/.local/state/komainu/credentials.json",
  "**/.env",
  "**/.env.local",
  "**/.env.production",
  "**/*.pem",
  "**/*.key",
]
