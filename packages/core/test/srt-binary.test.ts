import { describe, expect, test } from "bun:test"
import { chmodSync, mkdirSync, mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { decideFileAccess } from "../src/policy.js"
import { sandboxToolPaths, srtBinary } from "../src/sandbox.js"

// install.sh puts a Bun-run srt next to komainu when Node.js is missing; komainu must find it even when that
// folder isn't on PATH yet (a beginner who skipped the PATH step).
const script = (path: string) => { writeFileSync(path, "#!/bin/sh\n"); chmodSync(path, 0o755) }

describe("srtBinary", () => {
  test("prefers the srt installed next to komainu", () => {
    const bin = mkdtempSync(join(tmpdir(), "srt-bin-"))
    script(join(bin, "srt"))
    expect(srtBinary(join(bin, "komainu"), "/nonexistent", "/nonexistent")).toBe(join(bin, "srt"))
  })

  test("falls back to ~/.local/bin/srt when it isn't on PATH", () => {
    const home = mkdtempSync(join(tmpdir(), "srt-home-"))
    mkdirSync(join(home, ".local", "bin"), { recursive: true })
    script(join(home, ".local", "bin", "srt"))
    expect(srtBinary("/nonexistent/komainu", home, "/nonexistent")).toBe(join(home, ".local", "bin", "srt"))
  })

  test("is undefined when there is no srt anywhere", () => {
    expect(srtBinary("/nonexistent/komainu", "/nonexistent", "/nonexistent")).toBeUndefined()
  })
})

describe("sandboxToolPaths", () => {
  test("the write tool can't silently replace srt or what its wrapper runs", () => {
    const bin = mkdtempSync(join(tmpdir(), "srt-guard-"))
    const pkg = join(bin, "share", "node_modules", "@anthropic-ai", "sandbox-runtime")
    const cli = join(pkg, "dist", "cli.js")
    mkdirSync(join(pkg, "dist"), { recursive: true })
    writeFileSync(cli, "")
    writeFileSync(join(bin, "srt"), `#!/bin/sh\nexec "/usr/bin/bun" --bun "${cli}" "$@"\n`)
    const cfg = { mode: "balanced" as const, workspace: "/tmp/project", protectedPaths: sandboxToolPaths(join(bin, "srt"), join(bin, "komainu")) }
    for (const target of [join(bin, "srt"), join(bin, "komainu"), join(bin, "komainu-update"), cli, join(bin, "share", "node_modules", "zod", "index.js")])
      expect(decideFileAccess("write", target, cfg, { tainted: false }).effect).not.toBe("allow")
  })
})
