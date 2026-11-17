/**
 * Channel between the server plugin (decides, waits) and the TUI plugin (shows things).
 *   question  Effort Advisor suggestion, answered with `answer`
 *   notice    one-way heads-up, e.g. why a permission prompt appeared (threat memory)
 *   image     Image guard found something in an attached image, answered with `imageAnswer`
 */
export const ADVISOR_RPC = {
  id: "komainu.advisor",
  methods: {
    imageAnswer: {
      input: {
        type: "object",
        properties: { id: { type: "string" }, choice: { type: "string", enum: ["send", "cancel"] } },
        required: ["id", "choice"],
        additionalProperties: false,
      },
      output: { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"] },
    },
    answer: {
      input: {
        type: "object",
        properties: { id: { type: "string" }, choice: { type: "string", enum: ["switch", "keep", "auto"] } },
        required: ["id", "choice"],
        additionalProperties: false,
      },
      output: { type: "object", properties: { ok: { type: "boolean" } }, required: ["ok"] },
    },
  },
  events: {
    image: {
      schema: {
        type: "object",
        properties: {
          id: { type: "string" },
          sessionID: { type: "string" },
          directory: { type: "string" },
          name: { type: "string" },
          findings: { type: "array", items: { type: "object", properties: { rule: { type: "string" }, severity: { type: "string" }, message: { type: "string" } } } },
          text: { type: "string" },
          remembered: { type: "boolean" },
        },
        required: ["id", "sessionID", "directory", "name", "findings", "text"],
      },
    },
    question: {
      schema: {
        type: "object",
        properties: {
          id: { type: "string" },
          sessionID: { type: "string" },
          directory: { type: "string" },
          current: { type: "string" },
          target: { type: "string" },
          direction: { type: "string", enum: ["raise", "lower"] },
          level: { type: "string" },
          reasons: { type: "array", items: { type: "string" } },
        },
        required: ["id", "sessionID", "directory", "current", "target", "direction", "level", "reasons"],
      },
    },
    notice: {
      schema: {
        type: "object",
        properties: { sessionID: { type: "string" }, message: { type: "string" } },
        required: ["sessionID", "message"],
      },
    },
  },
} as const

export interface AdvisorQuestion {
  readonly id: string
  readonly sessionID: string
  /** Project the asking plugin instance belongs to; answers must be routed back to it. */
  readonly directory: string
  readonly current: string
  readonly target: string
  readonly direction: "raise" | "lower"
  readonly level: string
  readonly reasons: readonly string[]
}

export type AdvisorChoice = "switch" | "keep" | "auto"

/** How long a request waits for an answer before keeping the selected effort (e.g. headless runs). */
export const ADVISOR_TIMEOUT_MS = 45_000

export interface ImageAlert {
  readonly id: string
  readonly sessionID: string
  readonly directory: string
  readonly name: string
  readonly findings: ReadonlyArray<{ rule: string; severity: string; message: string }>
  /** what the model would read in the image */
  readonly text: string
  /** this exact image was flagged before */
  readonly remembered?: boolean
}

export type ImageChoice = "send" | "cancel"
