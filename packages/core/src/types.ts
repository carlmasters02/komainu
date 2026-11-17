export type Effect = "allow" | "ask" | "deny"
export type Severity = "info" | "low" | "medium" | "high" | "critical"

export interface Finding {
  readonly rule: string
  readonly severity: Severity
  readonly message: string
  readonly line?: number
  readonly file?: string
}

export interface Decision {
  readonly effect: Effect
  readonly findings: readonly Finding[]
  /** Human-readable reason, suitable for showing to the user and the model. */
  readonly reason?: string
}

const EFFECT_RANK: Record<Effect, number> = { allow: 0, ask: 1, deny: 2 }
const SEVERITY_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 }

export const strongest = (a: Effect, b: Effect): Effect => (EFFECT_RANK[a] >= EFFECT_RANK[b] ? a : b)

export const severityAtLeast = (s: Severity, min: Severity) => SEVERITY_RANK[s] >= SEVERITY_RANK[min]

export const maxSeverity = (findings: readonly Finding[]): Severity | undefined =>
  findings.reduce<Severity | undefined>(
    (max, f) => (max === undefined || SEVERITY_RANK[f.severity] > SEVERITY_RANK[max] ? f.severity : max),
    undefined,
  )

export const describe = (findings: readonly Finding[]) =>
  findings.map((f) => `[${f.severity}] ${f.rule}: ${f.message}`).join("\n")
