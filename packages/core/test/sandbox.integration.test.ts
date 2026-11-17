import { describe, expect, test } from "bun:test"
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { srtBinary, wrapCommand, writeSrtSettings } from "../src/index.js"

const srt = srtBinary()
// Some CI runners (e.g. Ubuntu 24.04 AppArmor) block unprivileged user namespaces; probe instead of assuming.
const ready = !!srt && (process.platform === "darwin" || !!Bun.which("bwrap")) && Bun.spawnSync([srt, "-c", "true"]).exitCode === 0

describe.skipIf(!ready)("srt sandbox (integration)", () => {
  const ws = mkdtempSync(join(tmpdir(), "komainu-sbx-"))
  writeFileSync(join(ws, ".env"), "SECRET=abc\n")
  writeFileSync(join(ws, "ok.txt"), "hi\n")
  mkdirSync(join(ws, ".komainu"), { recursive: true })
  const settings = writeSrtSettings({ workspace: ws, allowedDomains: ["registry.npmjs.org"] }, join(ws, ".komainu"))
  const run = (cmd: string) => Bun.spawnSync(["bash", "-c", wrapCommand(cmd, settings, srt!)], { cwd: ws, stderr: "pipe" })

  test("normal workspace reads/writes work", () => {
    expect(run("cat ok.txt && echo x > new.txt").exitCode).toBe(0)
  })
  test("secrets are unreadable", () => expect(run("cat .env").exitCode).not.toBe(0))
  test("guardrail files are read-only", () => expect(run("echo pwn > .komainu/x").exitCode).not.toBe(0))
  test("system paths are read-only", () => expect(run("touch /etc/komainu-pwned").exitCode).not.toBe(0))
  test("non-allowlisted network is blocked", () => expect(run("curl -sS -m 5 https://example.com").exitCode).not.toBe(0))
})
