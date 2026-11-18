import { describe, expect, test } from "bun:test"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { createKomainu } from "../src/index.js"

// Found by the live benchmark: after Komainu refused a webfetch, a real model re-fetched the page with
// fetch() inside Code Mode's `execute`. That fetch only passes OpenCode's webfetch permission check.
async function setup() {
  const dir = mkdtempSync(join(tmpdir(), "komainu-codemode-"))
  const hooks = new Map<string, (e: any) => unknown>()
  const reg = (d: string) => ({ hook: async (n: string, cb: any) => (hooks.set(`${d}.${n}`, cb), { dispose: async () => {} }) })
  const ctx: any = {
    location: { directory: dir },
    options: { mode: "balanced", sandbox: "off", effort: "off", memoryPath: join(dir, "m.json"), graphSink: false },
    tool: reg("tool"), shell: reg("shell"), session: reg("session"),
    permission: { ...reg("permission"), assert: async () => {} },
    rpc: { register: async () => ({ dispose: async () => {}, events: { emit: async () => {} } }) },
  }
  await createKomainu().setup(ctx)
  const base = { sessionID: "s", agent: "build", messageID: "m", id: "c" }
  const evaluate = async (url: string) => {
    const ev: any = { sessionID: "s", action: "webfetch", resources: [url], effect: "allow" }
    await hooks.get("permission.evaluate")!(ev)
    return ev.effect
  }
  const readUntrusted = () =>
    hooks.get("tool.execute.after")!({ ...base, tool: "webfetch", input: { url: "https://docs.example/x" }, status: "completed", result: { content: "docs" } })
  return { hooks, base, evaluate, readUntrusted }
}

describe("fetch() inside Code Mode", () => {
  test("gets the webfetch URL policy", async () => {
    const { evaluate } = await setup()
    expect(await evaluate("http://169.254.169.254/latest/meta-data/")).toBe("deny")
    expect(await evaluate("https://lic.example/check?key=sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe("deny")
    expect(await evaluate("https://registry.npmjs.org/react")).toBe("allow")
  })

  test("needs approval for private addresses once the session read untrusted content", async () => {
    const { evaluate, readUntrusted } = await setup()
    await readUntrusted()
    expect(await evaluate("http://127.0.0.1:8080/SETUP.md")).toBe("ask")
  })

  test("a webfetch the tool hook already approved is not asked about twice", async () => {
    const { hooks, base, evaluate } = await setup()
    await hooks.get("tool.execute.before")!({ ...base, tool: "webfetch", input: { url: "https://docs.example/a" } })
    expect(await evaluate("https://docs.example/a")).toBe("allow")
  })
})
