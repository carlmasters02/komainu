// Usage: bun fork/import-opencode-settings.ts   (run after fork/install.sh)
// Imports your OpenCode global config into Komainu: MCP servers, plugins, model, provider settings,
// agents, keybinds, theme, everything. Komainu's security plugin and permissions stay in charge.
const home = process.env.HOME
const src = `${home}/.config/opencode`
const dst = `${home}/.config/komainu/opencode.json`

// JSON with comments / trailing commas (opencode.jsonc) → plain JSON, string-aware
function parse(text: string) {
  let out = ""
  let i = 0
  let inStr = false
  while (i < text.length) {
    const c = text[i]
    const n = text[i + 1]
    if (inStr) {
      out += c
      if (c === "\\") { out += n; i += 2; continue }
      if (c === '"') inStr = false
      i++
      continue
    }
    if (c === '"') { inStr = true; out += c; i++; continue }
    if (c === "/" && n === "/") { while (i < text.length && text[i] !== "\n") i++; continue }
    if (c === "/" && n === "*") { i += 2; while (i < text.length && !(text[i] === "*" && text[i + 1] === "/")) i++; i += 2; continue }
    out += c
    i++
  }
  return JSON.parse(out.replace(/,(\s*[}\]])/g, "$1"))
}

async function read(path: string) {
  const f = Bun.file(path)
  return (await f.exists()) ? parse(await f.text()) : {}
}

const mine = {
  ...(await read(`${src}/config.json`)),
  ...(await read(`${src}/opencode.json`)),
  ...(await read(`${src}/opencode.jsonc`)),
}
const kom = await read(dst)
const komPlugin = kom.plugins.find((p: unknown) => JSON.stringify(p).includes("opencode-plugin"))
const myPlugins = [...(mine.plugins ?? []), ...(mine.plugin ?? [])].filter((p) => !JSON.stringify(p).includes("komainu"))

const merged = {
  ...mine,
  $schema: kom.$schema,
  plugins: [...myPlugins, komPlugin],
  permissions: kom.permissions, // Komainu's gatekeeping rules win
  agents: { ...(mine.agents ?? mine.agent ?? {}), ...kom.agents },
  update: "disable",
}
for (const legacy of ["plugin", "permission", "agent", "autoupdate"]) delete (merged as Record<string, unknown>)[legacy]

await Bun.write(dst, JSON.stringify(merged, null, 2) + "\n")

// custom agents, commands, skills, themes, plugin folders: copied without overwriting anything Komainu has
const { cpSync, existsSync, readdirSync, readFileSync, appendFileSync } = await import("node:fs")
const komDir = `${home}/.config/komainu`
const copied: string[] = []
if (existsSync(src))
  for (const entry of readdirSync(src)) {
    if (["opencode.json", "opencode.jsonc", "config.json", "AGENTS.md", "node_modules"].includes(entry)) continue
    cpSync(`${src}/${entry}`, `${komDir}/${entry}`, { recursive: true, force: false, errorOnExist: false })
    copied.push(entry)
  }
// global AGENTS.md rules: appended once
const marker = "# Imported from OpenCode"
if (existsSync(`${src}/AGENTS.md`) && !readFileSync(`${komDir}/AGENTS.md`, "utf8").includes(marker))
  appendFileSync(`${komDir}/AGENTS.md`, `\n\n${marker}\n\n${readFileSync(`${src}/AGENTS.md`, "utf8")}`)
console.log("✓ imported into", dst)
console.log("  MCP servers:", Object.keys(merged.mcp ?? {}).join(", ") || "(none)")
console.log("  plugins:", merged.plugins.length, `(yours: ${myPlugins.length} + Komainu)`)
console.log("  agents:", Object.keys(merged.agents).join(", "))
console.log("  copied:", copied.join(", ") || "(nothing else)")
console.log("Restart with: komainu service restart")
if (mine.permissions || mine.permission) console.log("  note: your old OpenCode permission rules were replaced by Komainu's (security first)")
