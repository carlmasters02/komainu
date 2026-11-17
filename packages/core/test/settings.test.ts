import { describe, expect, test } from "bun:test"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { cachedSettings, readSettings, writeSettings, DEFAULT_PROTECTED, decideFileAccess } from "../src/index.js"

describe("runtime settings", () => {
  const path = join(mkdtempSync(join(tmpdir(), "ks-")), "settings.json")
  test("missing file → empty", () => expect(readSettings(path)).toEqual({}))
  test("write/read round-trip and sanitising", () => {
    writeSettings(() => ({ effort: "auto", spend: { show: false, daily: 5 } }), path)
    expect(readSettings(path)).toEqual({ effort: "auto", spend: { show: false, daily: 5 } })
    writeFileSync(path, JSON.stringify({ effort: "max-yolo", spend: { daily: -3, show: "yes" } }))
    expect(readSettings(path)).toEqual({ spend: {} })
    writeFileSync(path, JSON.stringify({ effort: "ask" }))
    expect(readSettings(path)).toEqual({ effort: "suggest" }) // earlier name migrates
    writeFileSync(path, "{ not json")
    expect(readSettings(path)).toEqual({})
  })
  test("cached reader picks up changes", async () => {
    const read = cachedSettings(path)
    writeSettings(() => ({ effort: "suggest" }), path)
    expect(read().effort).toBe("suggest")
    await Bun.sleep(5)
    writeSettings(() => ({ effort: "off" }), path)
    expect(read().effort).toBe("off")
  })
  test("agent can't edit the settings file", () => {
    const cfg = { mode: "balanced" as const, workspace: "/w", protectedPaths: DEFAULT_PROTECTED }
    expect(decideFileAccess("write", "~/.local/state/komainu/settings.json", cfg, { tainted: false }).effect).toBe("ask")
  })
})
