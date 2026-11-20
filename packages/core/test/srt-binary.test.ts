import { describe, expect, test } from "bun:test"
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { srtBinary } from "../src/sandbox.js"

// install.sh puts a Bun-run srt next to komainu when Node.js is missing; komainu must find it even when that
// folder isn't on PATH yet (a beginner who skipped the PATH step).
const script = (path: string) => { writeFileSync(path, "#!/bin/sh\n"); chmodSync(path, 0o755) }

describe("srtBinary", () => {
  test("prefers the srt installed next to komainu", () => {
    const bin = mkdtempSync(join(tmpdir(), "srt-bin-"))
    script(join(bin, "srt"))
    expect(srtBinary(join(bin, "komainu"), "/nonexistent")).toBe(join(bin, "srt"))
  })

  test("falls back to ~/.local/bin/srt when it isn't on PATH", () => {
    const home = mkdtempSync(join(tmpdir(), "srt-home-"))
    mkdirSync(join(home, ".local", "bin"), { recursive: true })
    script(join(home, ".local", "bin", "srt"))
    const path = process.env.PATH
    process.env.PATH = "/nonexistent"
    try {
      expect(srtBinary("/nonexistent/komainu", home)).toBe(join(home, ".local", "bin", "srt"))
    } finally {
      process.env.PATH = path
    }
  })

  test("is undefined when there is no srt anywhere", () => {
    const path = process.env.PATH
    process.env.PATH = "/nonexistent"
    try {
      expect(srtBinary("/nonexistent/komainu", "/nonexistent")).toBeUndefined()
    } finally {
      process.env.PATH = path
    }
  })
})
