import { describe, expect, test } from "bun:test"
import { assessPrompt, decideEffort } from "../src/index.js"

describe("assessPrompt", () => {
  test.each(["run the tests", "git status", "show the last commit"])("minimal: %s", (p) => {
    expect(assessPrompt(p)).toMatchObject({ level: "minimal" })
  })

  test("max: several strong complexity signals", () => {
    expect(assessPrompt("Design the architecture for a multi-tenant system from scratch, investigate the race condition in the scheduler, and plan the migration step by step").level).toBe("max")
  })

  test.each([
    "rename getUser to fetchUser",
    "fix the typo in README.md",
    "add a docstring to parse_config",
    "what does this function do?",
  ])("low: %s", (p) => {
    const a = assessPrompt(p)
    expect(a.level).toBe("low")
    expect(a.confidence).toBeGreaterThanOrEqual(0.75)
  })

  test.each([
    "Refactor the entire auth module to use JWT and migrate all sessions",
    "Design the architecture for a multi-tenant billing system from scratch",
    "Investigate the root cause of the race condition in the job queue",
  ])("high: %s", (p) => {
    const a = assessPrompt(p)
    expect(a.level).toBe("high")
    expect(a.confidence).toBeGreaterThanOrEqual(0.65)
  })

  test("stack trace → at least medium", () => {
    const a = assessPrompt("getting this:\nTraceback (most recent call last):\n  File \"app.py\", line 3\nKeyError: 'id'")
    expect(a.level).toBe("medium")
  })

  test.each(["continue", "yes", "go ahead", "ok!"])("abstains on follow-up: %s", (p) => {
    expect(assessPrompt(p).confidence).toBe(0)
  })
})

describe("decideEffort picks from the model's own effort ladder", () => {
  const easy = assessPrompt("rename foo to bar") // low
  const trivial = assessPrompt("run the tests") // minimal
  const medium = assessPrompt("getting this:\nTraceback (most recent call last):\nKeyError: 'id'") // medium
  const hard = assessPrompt("Design the architecture for a distributed system from scratch") // high
  const huge = assessPrompt("Design the architecture for a multi-tenant system from scratch, investigate the race condition in the scheduler, and plan the migration step by step") // max

  const openai = ["minimal", "low", "medium", "high", "xhigh"]
  const budget = ["high", "max"] // token-budget models
  const toggle = ["none", "thinking"] // on/off models
  const full = ["low", "medium", "high", "max"]

  test("fits → silent", () => {
    expect(decideEffort(hard, "high", full).target).toBeUndefined()
    expect(decideEffort(medium, "medium", full).target).toBeUndefined()
  })
  test("lowers to the cheapest level that's still enough", () => {
    expect(decideEffort(easy, "max", full).target).toBe("low")
    expect(decideEffort(trivial, "xhigh", openai).target).toBe("minimal")
    expect(decideEffort(medium, "max", full).target).toBe("medium")
  })
  test("raises to the smallest level that's enough, including xhigh and max", () => {
    expect(decideEffort(huge, "medium", openai)).toMatchObject({ target: "xhigh", suggestion: "raise" })
    expect(decideEffort(huge, "high", full)).toMatchObject({ target: "max", suggestion: "raise" })
    expect(decideEffort(hard, "low", full)).toMatchObject({ target: "high", suggestion: "raise" })
  })
  test("caps a raise at the model's strongest level", () => {
    expect(decideEffort(huge, "medium", ["low", "medium", "high"])).toMatchObject({ target: "high" })
    expect(decideEffort(huge, "high", ["low", "medium", "high"]).target).toBeUndefined()
  })
  test("budget models (high/max)", () => {
    expect(decideEffort(huge, "high", budget).target).toBe("max")
    expect(decideEffort(easy, "max", budget).target).toBe("high") // cheapest it offers
  })
  test("on/off thinking models", () => {
    expect(decideEffort(hard, "none", toggle).target).toBe("thinking")
    expect(decideEffort(trivial, "thinking", toggle).target).toBe("none")
    expect(decideEffort(easy, "thinking", toggle).target).toBeUndefined() // "none" would be below what it needs
  })
  test("model default is treated as roughly medium", () => {
    expect(decideEffort(easy, undefined, full).target).toBe("low")
    expect(decideEffort(hard, undefined, full).target).toBe("high")
    expect(decideEffort(medium, undefined, full).target).toBeUndefined()
  })
  test("auto applies lowering only; raising stays a suggestion", () => {
    expect(decideEffort(easy, "high", full, { mode: "auto" })).toMatchObject({ variant: "low", action: "lower" })
    expect(decideEffort(hard, "low", full, { mode: "auto" })).toMatchObject({ variant: "low", action: "keep", suggestion: "raise" })
  })
  test("unknown variant names and low-confidence prompts are left alone", () => {
    expect(decideEffort(easy, "turbo", full).target).toBeUndefined()
    expect(decideEffort(assessPrompt("continue"), "max", full).target).toBeUndefined()
  })
})
