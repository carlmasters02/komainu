import { expect, test } from "bun:test"
import { existsSync, readFileSync, rmSync } from "node:fs"
import { srtBinary } from "@komainu/core"
import { runSelfTest } from "../src/selftest.js"

test("self-test: protections pass, the report is written, and (with srt) the sandbox checks pass", async () => {
  const r = await runSelfTest()
  try {
    expect(existsSync(r.path)).toBe(true)
    expect(readFileSync(r.path, "utf8")).toContain("# Komainu self-test")
    const failed = (area: string) => r.checks.filter((c) => c.area === area && c.status === "fail").map((c) => `${c.name}: ${c.detail}`)
    expect(failed("Protections")).toEqual([])
    expect(r.checks.find((c) => c.name === "prompt-injection attacks")?.status).toBe("pass")
    if (srtBinary()) expect(failed("Sandbox")).toEqual([])
  } finally {
    rmSync(r.path, { force: true })
  }
}, 180_000)
