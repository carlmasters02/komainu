/** @jsxImportSource @opentui/solid */
/**
 * Komainu's TUI side:
 *   Effort Advisor dialog  answers the server's "question" (sent after you submit a prompt, before it runs)
 *   prompt.footer.status   effort line: selected effort + advisor mode (+ what auto actually used)
 *   sidebar.content        spend: today / 7 days / 30 days (tokens on subscription plans), daily budget
 *   home.footer.status     the same spend summary on the home screen
 *   /advisor  /spend  /komainu   runtime switches, saved to the shared settings file (no restart)
 *   /komainu → Security graph     the audit log as a pipeline graph in your browser (local file, no account)
 *   /komainu → Threat memory      what Komainu remembers across projects; /komainu → Neo4j to share it
 *   sponsor welcome               shown once on first launch; opt-in, never changes your model
 * Names avoid OpenCode's built-ins (/effort is an alias of /variants; /usage and /stats exist).
 */
import type { Plugin } from "@opencode/plugin/tui"
import {
  readSettings, settingsPath, writeSettings, writeSecurityGraph, ThreatMemory, memoryPath, readNeo4jCredentials, writeNeo4jCredentials,
  parseAuraCredentials, validNeo4jUri, credentialsPath, findImageTools, srtBinary, type ImageGuardMode, type EffortMode, type KomainuSettings, type Neo4jCredentials,
} from "@komainu/core"
import { spawn } from "node:child_process"
import { readFileSync } from "node:fs"
import { homedir } from "node:os"
import { createMemo, createSignal, Show } from "solid-js"
import { ADVISOR_RPC, type AdvisorChoice, type AdvisorQuestion, type ImageAlert, type ImageChoice } from "./advisor-rpc.js"

type Ctx = Plugin.Context

interface Totals {
  readonly cost: number
  readonly tokens: number
}

interface Prefs {
  readonly mode: () => EffortMode
  readonly showSpend: () => boolean
  readonly daily: () => number | undefined
}

type Update = (fn: (s: KomainuSettings) => KomainuSettings) => void

const DAY = 86_400_000
const money = new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 2 })
const compact = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 })

const plugin: Plugin.Definition = {
  id: "komainu",
  setup: async (ctx) => {
    const options = ctx.options as { effort?: EffortMode | "ask"; budget?: { daily?: number } }
    const configured: EffortMode = options.effort === "ask" ? "suggest" : (options.effort ?? "suggest")
    const [settings, setSettings] = createSignal<KomainuSettings>(readSettings())
    const update: Update = (fn) => setSettings(writeSettings(fn))
    const prefs: Prefs = {
      mode: () => settings().effort ?? configured,
      showSpend: () => settings().spend?.show ?? true,
      daily: () => settings().spend?.daily ?? options.budget?.daily,
    }
    const spend = createSpend(ctx, prefs.daily)
    const disposers = [
      ctx.ui.slot({ append: "sidebar.content", render: () => <Show when={prefs.showSpend()}><SpendPanel ctx={ctx} spend={spend} /></Show> }),
      ctx.ui.slot({ append: "home.footer.status", render: () => <Show when={prefs.showSpend()}><SpendLine ctx={ctx} spend={spend} /></Show> }),
      ctx.ui.slot({ append: "prompt.footer.status", render: (input) => <Show when={prefs.mode() !== "off"}><EffortLine ctx={ctx} sessionID={input.sessionID} mode={prefs.mode()} /></Show> }),
      listenForQuestions(ctx, setSettings),
      listenForImages(ctx),
      ctx.client.rpc(ADVISOR_RPC).events.on("notice", (event) => {
        const n = event.data as unknown as { message: string }
        ctx.ui.toast.show({ variant: "warning", message: n.message })
      }),
    ]
    registerCommands(ctx, prefs, update, spend, settings)
    const welcome = setTimeout(() => void sponsorWelcome(ctx, settings, update), 1500)
    return () => {
      clearTimeout(welcome)
      spend.stop()
      for (const d of disposers) d()
    }
  },
}
export default plugin

// ---------------------------------------------------------------- effort advisor

const MODES: ReadonlyArray<{ value: EffortMode; title: string; description: string }> = [
  { value: "suggest", title: "Suggest", description: "after you send a prompt, suggest a better effort before it runs; silent when it fits" },
  { value: "auto", title: "Auto", description: "lower effort for simple prompts without asking (raising still asks)" },
  { value: "off", title: "Off", description: "never check" },
]

/** Shows the server's question as a dialog and sends the answer back. Dismissing the dialog keeps the effort. */
function listenForQuestions(ctx: Ctx, setSettings: (s: KomainuSettings) => void) {
  const rpc = ctx.client.rpc(ADVISOR_RPC)
  return rpc.events.on("question", async (event) => {
    const q = event.data as unknown as AdvisorQuestion
    const easier = q.direction === "lower"
    const why = q.reasons.length ? ` (${q.reasons.join(", ")})` : ""
    const choice = await ctx.ui.dialog.select<AdvisorChoice>({
      title: easier ? `⛩ This prompt looks simpler than "${q.current}" effort` : `⛩ This prompt looks harder than "${q.current}" effort`,
      current: "switch",
      options: [
        {
          value: "switch",
          title: `Switch to ${q.target}`,
          description: easier ? `saves tokens; looks ${q.level}-effort${why}` : `better results; looks ${q.level}-effort${why}`,
        },
        { value: "keep", title: `Keep ${q.current}` },
        ...(easier ? [{ value: "auto" as const, title: `Switch to ${q.target}, and do this automatically from now on`, description: "sets /advisor to Auto" }] : []),
      ],
    })
    const answer: AdvisorChoice = choice ?? "keep"
    if (answer !== "keep") ctx.ui.model.variant.set(q.target)
    // route the answer to the plugin instance of the project that asked (one instance per project)
    await rpc.answer({ id: q.id, choice: answer }, { location: { directory: q.directory } }).catch(() => undefined)
    if (answer === "auto") {
      setSettings(readSettings())
      ctx.ui.toast.show({ variant: "success", message: "Effort Advisor: auto" })
    }
  })
}

function shortFinding(rule: string): string {
  if (rule === "image/scaling-text") return "text only visible when downscaled"
  if (rule === "image/faint-text") return "faint hidden text"
  if (rule.startsWith("image/text-")) return "injection-like text"
  if (rule.startsWith("image/metadata-")) return "injection in metadata"
  if (rule === "image/polyglot") return "hidden file inside"
  if (rule === "image/trailing-data") return "extra data after image"
  if (rule === "image/bomb") return "decompression bomb"
  if (rule.startsWith("image/svg-")) return "active SVG content"
  if (rule === "memory/flagged-image") return "flagged before"
  return rule.replace(/^image\//, "").replace(/-/g, " ")
}

/** Image guard: shows what's wrong with an attached image and what the model would read; you decide. */
function listenForImages(ctx: Ctx) {
  const rpc = ctx.client.rpc(ADVISOR_RPC)
  return rpc.events.on("image", async (event) => {
    const a = event.data as unknown as ImageAlert
    const top = [...new Set(a.findings.map((f) => shortFinding(f.rule)))].slice(0, 1).join(", ")
    let choice: ImageChoice | "show" | undefined
    do {
      choice = await ctx.ui.dialog.select<ImageChoice | "show">({
        title: `⛩ Image guard: "${a.name}" ${a.remembered ? "was flagged before" : "may contain a hidden prompt injection"}`,
        current: "cancel",
        options: [
          { value: "cancel", title: "Don't send", description: top },
          ...(a.text ? [{ value: "show" as const, title: "Show what the model would read" }] : []),
          { value: "send", title: "Send anyway", description: "session becomes untrusted" },
        ],
      })
      if (choice === "show")
        await ctx.ui.dialog.alert({ title: `Text the model would read in "${a.name}"`, message: a.text.slice(0, 1500) || "(no text found)" })
    } while (choice === "show")
    const answer: ImageChoice = choice ?? "cancel"
    await rpc.imageAnswer({ id: a.id, choice: answer }, { location: { directory: a.directory } }).catch(() => undefined)
    if (answer === "cancel") ctx.ui.toast.show({ variant: "warning", message: `Image guard: "${a.name}" not sent. Remove it from the prompt and try again.` })
  })
}

function EffortLine(props: { ctx: Ctx; sessionID?: string; mode: EffortMode }) {
  const theme = props.ctx.theme
  const state = createMemo(() => {
    const model = props.ctx.ui.model.current()
    if (!model) return
    const messages = props.sessionID ? props.ctx.data.session.message.list(props.sessionID) : []
    const assistant = [...messages].reverse().find((m) => m.type === "assistant")
    const used = assistant?.type === "assistant" ? assistant.model.variant : undefined
    return { selected: model.variant ?? "default", used }
  })
  return (
    <Show when={state()}>
      {(s) => (
        <box flexDirection="row" gap={1}>
          <text fg={theme.text.muted}>⛩ effort {s().selected} · advisor {props.mode}</text>
          <Show when={props.mode === "auto" && s().used && s().used !== s().selected}>
            <text fg={theme.text.muted}>· last ran {s().used}</text>
          </Show>
        </box>
      )}
    </Show>
  )
}

// ---------------------------------------------------------------- commands

function registerCommands(ctx: Ctx, prefs: Prefs, update: Update, spend: Spend, settings: () => KomainuSettings) {
  const advisor = async () => {
    const choice = await ctx.ui.dialog.select<EffortMode>({
      title: "Komainu Effort Advisor",
      current: prefs.mode(),
      options: MODES.map((m) => ({ title: m.title, value: m.value, description: m.description })),
    })
    if (!choice) return
    update((s) => ({ ...s, effort: choice }))
    ctx.ui.toast.show({ variant: "success", message: `Effort Advisor: ${choice}` })
  }

  const spendMenu = async () => {
    type Action = "show" | "hide" | "budget" | "nobudget"
    const choice = await ctx.ui.dialog.select<Action>({
      title: "Komainu spend tracker",
      options: [
        prefs.showSpend() ? { title: "Hide spend tracker", value: "hide" as const } : { title: "Show spend tracker", value: "show" as const },
        { title: "Set daily budget…", value: "budget" as const, description: prefs.daily() ? `currently ${money.format(prefs.daily()!)}` : "warns at 80% and 100%" },
        ...(prefs.daily() ? [{ title: "Remove daily budget", value: "nobudget" as const }] : []),
      ],
    })
    if (!choice) return
    if (choice === "show" || choice === "hide") update((s) => ({ ...s, spend: { ...s.spend, show: choice === "show" } }))
    if (choice === "nobudget") update((s) => ({ ...s, spend: { show: s.spend?.show } }))
    if (choice === "budget") {
      const raw = await ctx.ui.dialog.prompt({ title: "Daily budget (USD)", placeholder: "e.g. 5", value: prefs.daily()?.toString() })
      const daily = Number(raw)
      if (!raw || !(daily > 0)) return
      update((s) => ({ ...s, spend: { ...s.spend, daily } }))
      void spend.refresh()
    }
    ctx.ui.toast.show({ variant: "success", message: "Spend tracker updated" })
  }

  const hub = async () => {
    type Item = "graph" | "memory" | "images" | "neo4j" | "advisor" | "spend" | "sponsors" | "about"
    const remembered = new ThreatMemory().list().length
    const memoryOn = settings().memory?.enabled !== false
    const neo4j = readNeo4jCredentials()
    const choice = await ctx.ui.dialog.select<Item>({
      title: "⛩ Komainu",
      options: [
        { title: "Security graph", value: "graph", description: "opens in your browser" },
        { title: `Threat memory: ${memoryOn ? `${remembered} remembered` : "off"}`, value: "memory", description: "across projects" },
        { title: `Image guard: ${imageMode(settings, ctx)}`, value: "images", description: "checks attached images" },
        { title: `Neo4j: ${neo4j ? hostLabel(neo4j.uri) : "not connected"}`, value: "neo4j", description: "optional" },
        { title: `Effort Advisor: ${prefs.mode()}`, value: "advisor", description: "/advisor" },
        { title: `Spend tracker: ${prefs.showSpend() ? "shown" : "hidden"}${prefs.daily() ? `, budget ${money.format(prefs.daily()!)}/day` : ""}`, value: "spend", description: "/spend" },
        { title: "Sponsors", value: "sponsors", description: settings().sponsors?.enabled === false ? "messages off" : "ai&" },
        { title: "Where things live", value: "about" },
      ],
    })
    if (choice === "graph") return openGraph(ctx)
    if (choice === "memory") return memoryMenu(ctx, update, settings)
    if (choice === "neo4j") return neo4jMenu(ctx)
    if (choice === "images") return imageMenu(ctx, settings, update)
    if (choice === "advisor") return advisor()
    if (choice === "spend") return spendMenu()
    if (choice === "sponsors") return sponsorsMenu(ctx, settings, update)
    if (choice === "about")
      await ctx.ui.dialog.alert({
        title: "Komainu",
        message: [
          `Settings (/advisor, /spend): ${settingsPath()}`,
          `Threat memory: ${memoryPath()}`,
          `Integration credentials: ${credentialsPath()} (agent can't read it)`,
          "Security audit log: <project>/.komainu/audit.jsonl",
          "Security graph: <project>/.komainu/graph.html",
          "Security defaults: ~/.config/komainu/opencode.json",
        ].join("\n"),
      })
  }

  ctx.keymap.layer(() => ({
    mode: "global",
    commands: [
      { id: "komainu.advisor", title: "Komainu: Effort Advisor mode", group: "Komainu", slash: { name: "advisor" }, palette: true, run: advisor },
      { id: "komainu.spend", title: "Komainu: spend tracker", group: "Komainu", slash: { name: "spend" }, palette: true, run: spendMenu },
      { id: "komainu.menu", title: "Komainu", group: "Komainu", slash: { name: "komainu" }, palette: true, run: hub },
      { id: "komainu.graph", title: "Komainu: security graph", group: "Komainu", palette: true, run: () => openGraph(ctx) },
    ],
  }))
}

// ---------------------------------------------------------------- security graph + threat memory

const hostLabel = (uri: string) => uri.replace(/^[a-z+]+:\/\//, "").split("/")[0] ?? uri
const projectDir = (ctx: Ctx) => ctx.location?.directory ?? process.cwd()

/** Opens a local file in the default browser; silent if there's no opener (the toast still shows the path). */
function openExternal(path: string) {
  const wsl = process.platform === "linux" && /microsoft/i.test(safeRead("/proc/version"))
  const [cmd, args] =
    process.platform === "darwin" ? ["open", [path]] :
    process.platform === "win32" ? ["cmd", ["/c", "start", "", path]] :
    wsl ? ["wslview", [path]] : ["xdg-open", [path]]
  try {
    const child = spawn(cmd as string, args as string[], { detached: true, stdio: "ignore" })
    child.on("error", () => undefined)
    child.unref()
  } catch {}
}

function safeRead(path: string) {
  try {
    return readFileSync(path, "utf8")
  } catch {
    return ""
  }
}

async function openGraph(ctx: Ctx) {
  try {
    const { path, graph } = writeSecurityGraph(projectDir(ctx))
    openExternal(path)
    const s = graph.stats
    ctx.ui.toast.show({
      variant: "success",
      message: `Security graph: ${s.blocked ?? 0} blocked · ${s.asked ?? 0} asked · ${s.flagged ?? 0} injection${s.flagged === 1 ? "" : "s"} flagged — ${path.replace(homedir(), "~")}`,
    })
  } catch (e) {
    ctx.ui.toast.show({ variant: "error", message: `Couldn't build the security graph: ${(e as Error).message}` })
  }
}

async function memoryMenu(ctx: Ctx, update: Update, settings: () => KomainuSettings) {
  const memory = new ThreatMemory()
  const on = settings().memory?.enabled !== false
  type Action = "toggle" | "forget" | `show:${string}`
  const items = memory.list().slice(0, 30)
  const choice = await ctx.ui.dialog.select<Action>({
    title: `Threat memory (${items.length} remembered)`,
    placeholder: "only ever makes Komainu stricter: flagged sources and denied domains ask before use",
    options: [
      { title: on ? "Turn threat memory off" : "Turn threat memory on", value: "toggle" },
      ...(items.length ? [{ title: "Forget everything", value: "forget" as const }] : []),
      ...items.map((i) => ({
        title: i.key, value: `show:${i.key}` as const, category: i.kind === "domain" ? "Denied domains" : "Flagged sources",
        description: `${i.count}× · last ${i.last.slice(0, 10)} · ${i.reasons.slice(0, 3).join(", ")}`,
      })),
    ],
  })
  if (!choice) return
  if (choice === "toggle") update((s) => ({ ...s, memory: { enabled: !on } }))
  if (choice === "forget" && (await ctx.ui.dialog.confirm({ title: "Forget everything?", message: "Komainu will stop recognising sources and domains it flagged before." }))) memory.forget()
  if (choice.startsWith("show:")) {
    const key = choice.slice(5)
    const i = memory.lookup(key)
    if (!i) return
    const forget = await ctx.ui.dialog.confirm({
      title: key,
      message: `Seen ${i.count}× (first ${i.first.slice(0, 10)}, last ${i.last.slice(0, 10)})\nWhy: ${i.reasons.join(", ")}\nProjects: ${i.projects.join(", ")}`,
      label: { confirm: "Forget this one", cancel: "Keep" },
    })
    if (forget) memory.forget(key)
    return
  }
  ctx.ui.toast.show({ variant: "success", message: "Threat memory updated" })
}

async function testNeo4j(c: Neo4jCredentials): Promise<string | undefined> {
  try {
    const neo4j = (await import("neo4j-driver")).default
    const d = neo4j.driver(c.uri, neo4j.auth.basic(c.user, c.password), { connectionTimeout: 8000 })
    try {
      await d.verifyConnectivity({ database: c.database })
    } finally {
      await d.close()
    }
    return undefined
  } catch (e) {
    return String((e as Error)?.message ?? e).split("\n")[0]
  }
}

async function neo4jMenu(ctx: Ctx) {
  const current = readNeo4jCredentials()
  type Action = "aura" | "manual" | "test" | "disconnect" | "help"
  const choice = await ctx.ui.dialog.select<Action>({
    title: current ? `Neo4j: ${hostLabel(current.uri)}` : "Connect Neo4j (optional)",
    placeholder: "Komainu works fully without this",
    options: [
      { title: "Import Aura credentials file…", value: "aura", description: "the .txt Aura gives you; the password is never shown" },
      { title: "Enter connection manually…", value: "manual", description: "local Neo4j (bolt://localhost:7687) or any URI" },
      ...(current ? [{ title: "Test connection", value: "test" as const }, { title: "Disconnect", value: "disconnect" as const }] : []),
      { title: "What gets sent?", value: "help" },
    ],
  })
  if (!choice) return
  if (choice === "help")
    return ctx.ui.dialog.alert({
      title: "Neo4j in Komainu",
      message:
        "Each audit event (already secret-redacted: tool, command/URL, which layer caught it, the outcome) becomes a node linked to its project, session, source and the hosts it touched.\n\nKomainu then asks the graph \"has this source or domain misbehaved before?\" across every project writing to it, and asks you before using it again. It can only make Komainu stricter.\n\nFile contents are never sent. Credentials live in a file the agent can't read.",
    })
  if (choice === "disconnect") {
    writeNeo4jCredentials(undefined)
    return ctx.ui.toast.show({ variant: "success", message: "Neo4j disconnected" })
  }
  let creds: Neo4jCredentials | undefined = current
  if (choice === "aura") {
    const raw = await ctx.ui.dialog.prompt({ title: "Path to the Aura credentials .txt", placeholder: "~/Downloads/Neo4j-xxxxxxxx-Created-….txt" })
    if (!raw) return
    const text = safeRead(raw.trim().replace(/^~(?=\/)/, homedir()).replace(/^["']|["']$/g, ""))
    creds = text ? parseAuraCredentials(text) : undefined
    if (!creds) return ctx.ui.toast.show({ variant: "error", message: "Couldn't find NEO4J_URI and NEO4J_PASSWORD in that file" })
  }
  if (choice === "manual") {
    const uri = (await ctx.ui.dialog.prompt({ title: "Neo4j URI", placeholder: "neo4j+s://xxxx.databases.neo4j.io or bolt://localhost:7687", value: current?.uri }))?.trim()
    if (!uri) return
    if (!validNeo4jUri(uri)) return ctx.ui.toast.show({ variant: "error", message: "Expected neo4j://, neo4j+s://, bolt:// or bolt+s://" })
    const user = (await ctx.ui.dialog.prompt({ title: "Username", value: current?.user ?? "neo4j" }))?.trim() || "neo4j"
    const password = await ctx.ui.dialog.prompt({ title: "Password (visible while typing)", description: "Prefer the Aura file import if anyone can see your screen" })
    if (!password) return
    creds = { uri, user, password }
  }
  if (!creds) return
  ctx.ui.toast.show({ variant: "info", message: `Connecting to ${hostLabel(creds.uri)}…` })
  const error = await testNeo4j(creds)
  if (error) return ctx.ui.toast.show({ variant: "error", message: `Neo4j: ${error}` })
  if (choice !== "test") writeNeo4jCredentials(creds)
  ctx.ui.toast.show({ variant: "success", message: `Neo4j connected: ${hostLabel(creds.uri)} — new security events will appear there` })
}

// ---------------------------------------------------------------- image guard

const imageMode = (settings: () => KomainuSettings, ctx: Ctx): ImageGuardMode =>
  settings().images?.mode ?? (ctx.options as { imageGuard?: ImageGuardMode }).imageGuard ?? "ask"

async function imageMenu(ctx: Ctx, settings: () => KomainuSettings, update: Update) {
  const tools = findImageTools()
  const ocr = !tools.tesseract ? "text recognition off: install tesseract" : !srtBinary() ? "text recognition off: needs the sandbox (srt)" : `text recognition on${tools.magick ? "" : " (install ImageMagick for the downscale check)"}`
  const choice = await ctx.ui.dialog.select<ImageGuardMode>({
    title: "Image guard",
    placeholder: `Attach images with Ctrl+V or drag-and-drop · ${ocr}`,
    current: imageMode(settings, ctx),
    options: [
      { value: "ask", title: "Ask", description: "if an image looks poisoned, show what the model would read and ask" },
      { value: "block", title: "Block", description: "never send images that look poisoned" },
      { value: "off", title: "Off", description: "don't check images" },
    ],
  })
  if (!choice) return
  update((s) => ({ ...s, images: { mode: choice } }))
  ctx.ui.toast.show({ variant: "success", message: `Image guard: ${choice}` })
}

// ---------------------------------------------------------------- sponsors (optional, opt-in)

/** Only claims we can verify from ai&'s public event listing. Komainu works with any provider. */
const AIAND = {
  title: "Sponsor · ai&",
  message:
    "ai& runs AI inference on GPUs in Japan, with open models like Kimi and DeepSeek behind an OpenAI-compatible API.\n\nKomainu works with any provider. Connecting ai& is optional and never changes your current model.\n\nTurn sponsor messages off any time: /komainu → Sponsors.",
}

async function connectAiand(ctx: Ctx, update: Update) {
  update((s) => ({ ...s, sponsors: { ...s.sponsors, aiand: "connected" } }))
  ctx.keymap.dispatch("provider.connect")
  ctx.ui.toast.show({ variant: "info", message: "Pick ai& in the list to connect it" })
}

async function sponsorWelcome(ctx: Ctx, settings: () => KomainuSettings, update: Update) {
  const s = settings().sponsors
  if (s?.enabled === false || s?.aiand) return
  if (ctx.ui.router.current().type !== "home") return // only on a fresh start, never mid-session
  const yes = await ctx.ui.dialog.confirm({ title: AIAND.title, message: AIAND.message, label: { confirm: "Connect", cancel: "Not now" } })
  if (yes) return connectAiand(ctx, update)
  update((cur) => ({ ...cur, sponsors: { ...cur.sponsors, aiand: "dismissed" } }))
}

async function sponsorsMenu(ctx: Ctx, settings: () => KomainuSettings, update: Update) {
  const enabled = settings().sponsors?.enabled !== false
  type Action = "aiand" | "toggle"
  const choice = await ctx.ui.dialog.select<Action>({
    title: "Sponsors",
    placeholder: "Komainu is free and works with any provider; sponsors are optional",
    options: [
      { title: "ai& — inference on GPUs in Japan", value: "aiand", description: "open models (Kimi, DeepSeek), OpenAI-compatible API · connect" },
      { title: enabled ? "Turn sponsor messages off" : "Turn sponsor messages on", value: "toggle" },
    ],
  })
  if (choice === "aiand") return connectAiand(ctx, update)
  if (choice === "toggle") {
    update((s) => ({ ...s, sponsors: { ...s.sponsors, enabled: !enabled } }))
    ctx.ui.toast.show({ variant: "success", message: `Sponsor messages ${enabled ? "off" : "on"}` })
  }
}

// ---------------------------------------------------------------- spend

function createSpend(ctx: Ctx, dailyBudget: () => number | undefined) {
  const [totals, setTotals] = createSignal<{ today: Totals; week: Totals; month: Totals }>()
  let warned = 0
  const timezone = Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"
  const range = async (from: number): Promise<Totals> => {
    const s = await ctx.client.experimental.session.stats({ from, timezone, tools: "none" })
    const t = s.tokens
    return { cost: s.cost, tokens: t.input + t.output + t.reasoning + t.cache.read + t.cache.write }
  }
  const refresh = async () => {
    const midnight = new Date()
    midnight.setHours(0, 0, 0, 0)
    const now = Date.now()
    const [today, week, month] = await Promise.all([range(midnight.getTime()), range(now - 7 * DAY), range(now - 30 * DAY)]).catch(
      () => [undefined, undefined, undefined],
    )
    if (!today || !week || !month) return
    setTotals({ today, week, month })
    const budget = dailyBudget()
    if (budget && budget > 0) {
      const level = today.cost >= budget ? 2 : today.cost >= budget * 0.8 ? 1 : 0
      if (level > warned)
        ctx.ui.toast.show({
          variant: level === 2 ? "error" : "warning",
          message: `Komainu: today's spend ${money.format(today.cost)} is ${level === 2 ? "over" : "at 80% of"} your ${money.format(budget)} daily budget`,
        })
      warned = Math.max(warned, level)
    }
  }
  void refresh()
  const timer = setInterval(() => void refresh(), 30_000)
  return { totals, dailyBudget, refresh, stop: () => clearInterval(timer) }
}

type Spend = ReturnType<typeof createSpend>

const fmt = (t: Totals, subscription: boolean) => (subscription ? `${compact.format(t.tokens)} tok` : money.format(t.cost))

function SpendLine(props: { ctx: Ctx; spend: Spend }) {
  const theme = props.ctx.theme
  return (
    <Show when={props.spend.totals()}>
      {(t) => {
        const sub = () => t().month.cost === 0 && t().month.tokens > 0
        return (
          <text fg={theme.text.muted}>
            {sub() ? "usage" : "spend"} today {fmt(t().today, sub())} · 7d {fmt(t().week, sub())} · 30d {fmt(t().month, sub())}
          </text>
        )
      }}
    </Show>
  )
}

function SpendPanel(props: { ctx: Ctx; spend: Spend }) {
  const theme = props.ctx.theme
  return (
    <Show when={props.spend.totals()}>
      {(t) => {
        const sub = () => t().month.cost === 0 && t().month.tokens > 0
        const over = () => !!props.spend.dailyBudget() && t().today.cost >= props.spend.dailyBudget()! * 0.8
        return (
          <box>
            <text fg={theme.text.base}>
              <b>{sub() ? "Usage" : "Spend"}</b>
            </text>
            <text fg={over() ? theme.text.feedback.warning.base : theme.text.muted}>
              today {fmt(t().today, sub())}
              {props.spend.dailyBudget() && !sub() ? ` / ${money.format(props.spend.dailyBudget()!)}` : ""}
            </text>
            <text fg={theme.text.muted}>7 days {fmt(t().week, sub())}</text>
            <text fg={theme.text.muted}>30 days {fmt(t().month, sub())}</text>
          </box>
        )
      }}
    </Show>
  )
}
