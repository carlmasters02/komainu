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
    const srt = srtBinary()
    const canRun = !!srt && Bun.spawnSync([srt, "-c", "true"]).exitCode === 0
    if (canRun) expect(failed("Sandbox")).toEqual([])
    // Where the sandbox can't start (e.g. Ubuntu 24.04 CI runners), the self-test must say so, with the fix.
    else if (srt) expect(r.checks.find((c) => c.name === "runs commands")?.status).toBe("fail")
  } finally {
    rmSync(r.path, { force: true })
  }
}, 180_000)
