/**
 * Effort Advisor: estimates how much reasoning effort a prompt needs, using free local rules (0 tokens).
 * Used to lower effort for simple prompts (saving tokens) and to hint when a prompt looks harder than
 * the selected effort. It deliberately abstains when unsure: a wrong downgrade costs more than it saves.
 */

export type EffortLevel = "minimal" | "low" | "medium" | "high" | "max"

export interface EffortAssessment {
  readonly level: EffortLevel
  /** 0..1; 0 means "abstain" (e.g. a context-dependent follow-up like "continue"). */
  readonly confidence: number
  readonly reasons: readonly string[]
}

const FOLLOW_UP = /^\s*(?:ok(?:ay)?|yes|yep|sure|continue|go(?: ahead| on)?|do it|proceed|next|thanks?|thank you|keep going|sounds good|y)\s*[.!]*\s*$/i

const LOW = [
  /\b(?:rename|typo|spelling|reformat|format(?:ting)?|indent(?:ation)?|lint|prettier)\b/i,
  /\b(?:add|update|fix|write)\s+(?:a\s+)?(?:comment|docstring|log(?:ging)? line|import|type annotation)s?\b/i,
  /\bbump\s+(?:the\s+)?version\b/i,
  /^\s*(?:run|show|list|print|open|read|cat)\b/i,
  /\b(?:what (?:is|does)|where is|which file)\b/i,
  /\bgit\s+(?:status|log|diff|add|commit|stash)\b/i,
  /\b(?:translate|convert)\s+(?:this|the)\s+(?:string|text|json|yaml)\b/i,
]

const HIGH = [
  /\b(?:architect(?:ure)?|system design|design (?:a|the) (?:system|architecture|api|schema))\b/i,
  /\b(?:refactor|rewrite|restructure|migrate|port)\b.{0,40}\b(?:entire|whole|all|across|codebase|project|module|from \w+ to)\b/i,
  /\b(?:from scratch|end[- ]to[- ]end|full[- ]stack)\b/i,
  /\b(?:race condition|deadlock|memory leak|concurren(?:cy|t)|thread[- ]safe|data corruption)\b/i,
  /\b(?:root cause|investigate|figure out why|debug why|why (?:does|is|doesn't|isn't|won't))\b/i,
  /\b(?:security (?:audit|review)|threat model|vulnerabilit(?:y|ies)|exploit)\b/i,
  /\b(?:optimi[sz]e|performance|profil(?:e|ing)|scal(?:e|ability))\b.{0,30}\b(?:system|service|query|pipeline|app)\b/i,
  /\b(?:implement|build|create)\b.{0,30}\b(?:feature|system|service|engine|framework|compiler|parser|protocol)\b/i,
  /\b(?:plan|step[- ]by[- ]step|multi[- ]step|several|multiple files)\b/i,
]

/** Bare one-liners that need almost no reasoning ("run the tests", "git status"). */
const TRIVIAL = /^\s*(?:run|show|list|print|open|cat|git\s+(?:status|log|diff))\b[^\n]{0,40}$/i

const PATH_LIKE = /(?:^|[\s`'"(@])[\w./-]+\.(?:ts|tsx|js|jsx|py|go|rs|java|rb|php|cs|cpp|c|h|swift|kt|sql|json|ya?ml|toml|md|sh)\b/g

export function assessPrompt(text: string): EffortAssessment {
  const t = text.trim()
  if (!t || FOLLOW_UP.test(t)) return { level: "medium", confidence: 0, reasons: ["follow-up depends on earlier context"] }

  const reasons: string[] = []
  const low = LOW.filter((r) => r.test(t)).length
  const high = HIGH.filter((r) => r.test(t)).length
  const files = new Set((t.match(PATH_LIKE) ?? []).map((m) => m.trim())).size
  const codeBlocks = (t.match(/```/g) ?? []).length / 2
  const trace = /\b(?:Traceback|Exception|Error:|panic:|segfault)\b|^\s+at \S+\s*\(/m.test(t)
  const long = t.length > 600

  if (high > 0) reasons.push(`${high} complexity signal(s)`)
  if (low > 0) reasons.push(`${low} simple-task signal(s)`)
  if (files > 1) reasons.push(`${files} files referenced`)
  if (trace) reasons.push("contains an error/stack trace")
  if (long) reasons.push("long, detailed prompt")

  if (high >= 3 || (high >= 2 && (long || files >= 3))) return { level: "max", confidence: 0.8, reasons }
  if (high >= 2 || (high >= 1 && (long || files >= 3))) return { level: "high", confidence: 0.85, reasons }
  if (high === 1) return { level: "high", confidence: 0.65, reasons }
  if (low > 0 && !trace && !long && codeBlocks < 1 && files === 0 && TRIVIAL.test(t))
    return { level: "minimal", confidence: 0.75, reasons }
  if (low > 0 && !trace && !long && codeBlocks < 1 && files <= 1)
    return { level: "low", confidence: t.length < 120 ? 0.85 : 0.75, reasons }
  if (trace || files >= 2 || codeBlocks >= 1) return { level: "medium", confidence: 0.7, reasons }
  return { level: "medium", confidence: 0.55, reasons: reasons.length ? reasons : ["ordinary coding request"] }
}

/**
 * Effort ladder for the variant IDs OpenCode generates: effort models (none…max), budget models (high, max),
 * and on/off models (none, thinking). Variants with unknown IDs are never offered.
 */
export const EFFORT_RANK: Readonly<Record<string, number>> = {
  none: 0, minimal: 0, low: 1, medium: 2, high: 3, thinking: 3, xhigh: 4, max: 5,
}
const LEVEL_RANK: Record<EffortLevel, number> = { minimal: 0, low: 1, medium: 2, high: 3, max: 4 }
/** The model's default effort isn't reported; treat it as middle-of-the-road so clear mismatches still surface. */
const DEFAULT_RANK = 2

export interface EffortDecision {
  /** Variant to use for this request (auto mode may lower it; otherwise the selection). */
  readonly variant: string | undefined
  readonly action: "lower" | "keep"
  /** Set when the selection doesn't fit the prompt: the model's own variant to offer instead. */
  readonly target?: string
  readonly suggestion?: "raise" | "lower"
  readonly assessment: EffortAssessment
}

/**
 * Decides whether the selected effort fits the prompt, picking from the variants this model actually offers.
 *   fits                 → no target (stay silent)
 *   prompt looks easier  → cheapest offered variant that still meets the need
 *   prompt looks harder  → smallest offered variant that meets the need (or the model's strongest, if none does)
 * In auto mode a lower target is applied directly; raising always needs the user (it costs more).
 */
export function decideEffort(
  assessment: EffortAssessment,
  current: string | undefined,
  available: readonly string[],
  opts: { readonly mode: "auto" | "suggest"; readonly minConfidence?: number } = { mode: "suggest" },
): EffortDecision {
  const keep: EffortDecision = { variant: current, action: "keep", assessment }
  const currentRank = current === undefined ? DEFAULT_RANK : EFFORT_RANK[current]
  if (currentRank === undefined || assessment.confidence < (opts.minConfidence ?? 0.7)) return keep

  const need = LEVEL_RANK[assessment.level]
  const ranked = available.filter((v) => EFFORT_RANK[v] !== undefined).sort((a, b) => EFFORT_RANK[a]! - EFFORT_RANK[b]!)
  const rank = (v: string) => EFFORT_RANK[v]!

  if (need > currentRank) {
    const stronger = ranked.filter((v) => rank(v) > currentRank)
    const target = stronger.find((v) => rank(v) >= need) ?? stronger.at(-1)
    return target ? { ...keep, target, suggestion: "raise" } : keep
  }
  // lower only when the prompt is clearly below the current effort, and only to a variant that still meets the need
  if (need >= currentRank) return keep
  const target = ranked.find((v) => rank(v) >= need && rank(v) < currentRank)
  if (!target) return keep
  if (opts.mode === "auto") return { variant: target, action: "lower", target, suggestion: "lower", assessment }
  return { ...keep, target, suggestion: "lower" }
}
