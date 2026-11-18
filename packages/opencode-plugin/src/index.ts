/**
 * Komainu for OpenCode v2.
 *
 *   opencode.json → "plugins": [{ "package": "@komainu/opencode", "options": { "mode": "balanced" } }]
 *
 * Hook map:
 *   tool  execute.before  → policy check (deny = throw, ask = permission prompt)  [prevent]
 *   shell create.before   → wrap the command in the OS sandbox (srt)              [contain]
 *   tool  execute.after   → redact secrets, taint + fence untrusted output,
 *                           scan written files and feed findings back to model     [detect + correct]
 *   permission evaluate   → escalate third-party tool calls in tainted sessions    [prevent]
 *   everything            → hash-chained audit log                                 [record]
 */
import type { Plugin } from "@opencode/plugin"
import {
  AuditLog, DEFAULT_ALLOWED_DOMAINS, DEFAULT_PROTECTED, decideFetch, decideFileAccess, decideShell, fence, formatFindingsForModel,
  isWrapped, redact, redactDeep, resolvePath, scanForInjection, scanSource, scanWithSemgrep, srtBinary, strongest, TaintTracker,
  wrapCommand, writeSrtSettings, assessPrompt, cachedSettings, decideEffort, writeSettings, ThreatMemory, sourceKey, sourceScope, hostOf, commandHosts, rememberableHosts, isMultiTenantHost,
  describeIncident, cachedNeo4jCredentials, scanImage, sniffType, describeOcrStatus, type ImageVerdict, type AuditEvent, type Decision, type Finding, type Incident, type Mode, type PolicyConfig,
} from "@komainu/core"
import { existsSync, readFileSync } from "node:fs"
import { createHash, randomUUID } from "node:crypto"
import { ADVISOR_RPC, ADVISOR_TIMEOUT_MS, type AdvisorChoice, type AdvisorQuestion, type ImageAlert, type ImageChoice } from "./advisor-rpc.js"
import { join } from "node:path"
import { createNeo4jSink, type GraphSink } from "./neo4j.js"

export interface KomainuOptions {
  /** strict: medium risks ask, guardrail/secret writes denied. balanced (default). permissive: only critical/taint. */
  readonly mode?: Mode
  /** auto (default): sandbox shell if `srt` is installed. required: refuse shell without it. off. */
  readonly sandbox?: "auto" | "required" | "off"
  readonly allowedDomains?: readonly string[]
  /** MCP/plugin tool names whose output you trust not to carry prompt injection. */
  readonly trustedTools?: readonly string[]
  /** Wrap untrusted tool output in <untrusted-content> fences (default true). */
  readonly fenceUntrusted?: boolean
  readonly scan?: { readonly builtin?: boolean; readonly semgrep?: boolean | string }
  readonly stateDir?: string
  /**
   * Effort Advisor default. suggest: when a prompt doesn't fit the selected effort, suggest a switch before it runs
   * (silent when it fits). auto: lower effort for simple prompts without asking (raising still asks). off: disabled.
   * Switch at runtime with /advisor; that choice overrides this default.
   */
  readonly effort?: "suggest" | "auto" | "off"
  /** Threat memory file (default ~/.local/state/komainu/threat-memory.json). Turn off with /komainu → Threat memory. */
  readonly memoryPath?: string
  /**
   * Image guard for images you attach (Ctrl+V / drag-and-drop). ask (default): if an image looks poisoned, show what
   * the model would read and ask before sending. block: never send flagged images. off. Switch with /komainu → Image guard.
   */
  readonly imageGuard?: "ask" | "block" | "off"
  /** Text recognition in images (needs tesseract; runs in the sandbox). Default true. */
  readonly imageOcr?: boolean
  /** Inject a graph sink (tests). Default: Neo4j when /komainu → Neo4j has credentials, otherwise nothing. */
  readonly graphSink?: GraphSink | false
}

type Ctx = Plugin.Context
type Input = Record<string, unknown>
type Content = string | ReadonlyArray<{ readonly type: string; readonly text?: string }>

const str = (v: unknown) => (typeof v === "string" ? v : undefined)

export function patchPaths(patchText: string): string[] {
  return [...patchText.matchAll(/^\*\*\* (?:Add|Update|Delete) File: (.+)$|^\*\*\* Move to: (.+)$/gm)].map((m) => (m[1] ?? m[2])!.trim())
}

function mapText(content: Content | undefined, fn: (s: string) => string): Content | undefined {
  if (content === undefined) return undefined
  if (typeof content === "string") return fn(content)
  return content.map((c) => (c.type === "text" && typeof c.text === "string" ? { ...c, text: fn(c.text) } : c))
}

function appendText(content: Content | undefined, extra: string): Content {
  if (content === undefined) return extra
  if (typeof content === "string") return content + extra
  return [...content, { type: "text", text: extra }]
}

export function createKomainu(options: KomainuOptions = {}) {
  const plugin: Plugin.Plugin = {
    id: "komainu",
    setup: async (ctx: Ctx) => {
      const opts = { ...options, ...(ctx.options as KomainuOptions | undefined) }
      const workspace = ctx.location.directory
      const stateDir = opts.stateDir ?? join(workspace, ".komainu")
      const policy: PolicyConfig = { mode: opts.mode ?? "balanced", workspace, protectedPaths: DEFAULT_PROTECTED }
      const taint = new TaintTracker(undefined, new Set(opts.trustedTools ?? []))
      const auditLog = new AuditLog(join(stateDir, "audit.jsonl"))
      const settings = cachedSettings()
      const sink = opts.graphSink === false ? undefined : (opts.graphSink ?? createNeo4jSink(cachedNeo4jCredentials(), workspace))
      const audit = { append: (event: AuditEvent) => {
        const entry = auditLog.append(event)
        sink?.push(entry)
        return entry
      } }
      // ---------------------------------------------------------------- remember (threat memory: stricter only)
      const memory = new ThreatMemory(opts.memoryPath)
      const memoryOn = () => settings().memory?.enabled !== false
      const remember = (key: string, reasons: readonly string[]) => {
        if (memoryOn()) memory.record(key, reasons, workspace)
      }
      /** Local memory first (instant); the shared graph adds what other projects/teammates saw. */
      const recall = async (key: string): Promise<Incident | undefined> => {
        if (!memoryOn()) return undefined
        const local = memory.lookup(key)
        const remote = sink ? await sink.recall(key).catch(() => undefined) : undefined
        if (!remote) return local
        if (!local) return remote
        return { ...local, count: Math.max(local.count, remote.count), projects: [...new Set([...local.projects, ...remote.projects])], reasons: [...new Set([...local.reasons, ...remote.reasons])] }
      }
      /** Adds what memory knows. allow → ask; an existing ask keeps its prompt but now says why it's familiar. Never loosens. */
      let notify: (sessionID: string, message: string) => void = () => {}
      const withRecall = async (decision: Decision, keys: string[], tool: string, sessionID: string, resource: string): Promise<Decision> => {
        if (decision.effect === "deny") return decision
        for (const key of keys) {
          const hit = await recall(key)
          if (!hit) continue
          const summary = describeIncident(hit, workspace)
          audit.append({ kind: "recall", sessionID, tool, key, resource, summary })
          notify(sessionID, `⛩ Threat memory: ${summary}`)
          const finding: Finding = { rule: hit.kind === "domain" ? "memory/denied-domain" : "memory/flagged-source", severity: "high", message: summary }
          return decision.effect === "ask"
            ? { ...decision, findings: [...decision.findings, finding], reason: `${decision.reason ?? ""}\n[komainu] Threat memory: ${summary}`.trim() }
            : { effect: "ask", findings: [...decision.findings, finding], reason: `[komainu] Threat memory: ${summary}` }
        }
        return decision
      }

      const sandboxMode = opts.sandbox ?? "auto"
      const srt = sandboxMode === "off" ? undefined : srtBinary()
      const srtSettings = srt ? writeSrtSettings({ workspace, allowedDomains: opts.allowedDomains ?? DEFAULT_ALLOWED_DOMAINS }, stateDir) : undefined
      const forceAsk = new Set<string>()
      /** URLs the webfetch tool hook already decided, so the permission check that follows doesn't ask twice. */
      const checkedFetch = new Set<string>()
      const fetchKeys = (url: string) => {
        const host = hostOf(url)
        const scope = sourceScope(url)
        return [scope && `url:${scope}`, host && !isMultiTenantHost(host) && `domain:${host}`].filter((k): k is string => !!k)
      }

      audit.append({ kind: "start", mode: policy.mode, sandbox: srt ? "srt" : sandboxMode === "off" ? "off" : "unavailable", workspace })

      const enforce = async (e: { sessionID: string; agent: string; tool: string }, decision: Decision, resources: string[]) => {
        const tainted = taint.isTainted(e.sessionID)
        audit.append({ kind: "decision", sessionID: e.sessionID, tool: e.tool, effect: decision.effect, resources, findings: decision.findings.map((f) => f.rule), tainted })
        if (decision.effect === "allow") return
        const reason = decision.reason ?? "Blocked by Komainu policy"
        const hosts = e.tool === "shell" ? rememberableHosts(resources[0] ?? "") : []
        if (decision.effect === "deny") {
          for (const h of hosts) remember(`domain:${h}`, ["blocked by policy"])
          const what = decision.findings.find((f) => f.severity === "critical" || f.severity === "high")?.message ?? reason.split("\n")[0]
          notify(e.sessionID, `⛩ Blocked ${e.tool}: ${what}`)
        }
        if (decision.effect === "deny") throw new Error(`[komainu] Blocked: ${reason}\nDo not try to work around this block; explain to the user what you were trying to do.`)
        const action = `komainu.${decision.findings.find((f) => f.severity !== "info")?.rule ?? e.tool}`
        if (policy.mode === "strict" || taint.isTainted(e.sessionID)) forceAsk.add(`${e.sessionID}|${action}`)
        try {
          await ctx.permission.assert({ sessionID: e.sessionID as never, agent: e.agent as never, action, resources, metadata: { reason, findings: decision.findings as unknown as Finding[] } as never })
        } catch (err) {
          audit.append({ kind: "reply", sessionID: e.sessionID, tool: e.tool, reply: "rejected", resources })
          for (const h of hosts) remember(`domain:${h}`, ["denied by you"])
          throw err
        }
        audit.append({ kind: "reply", sessionID: e.sessionID, tool: e.tool, reply: "approved", resources })
      }

      // ---------------------------------------------------------------- prevent
      await ctx.tool.hook("execute.before", async (e) => {
        const input = (e.input ?? {}) as Input
        const tctx = { tainted: taint.isTainted(e.sessionID) }
        switch (e.tool) {
          case "shell": {
            const command = str(input.command) ?? ""
            if (sandboxMode === "required" && !srt)
              throw new Error("[komainu] Shell is disabled: sandbox is required but `srt` is not installed (npm i -g @anthropic-ai/sandbox-runtime).")
            const decision = await withRecall(decideShell(command, policy, tctx), rememberableHosts(command).map((h) => `domain:${h}`), e.tool, e.sessionID, command)
            return enforce(e, decision, [command])
          }
          case "read": {
            const path = str(input.path)
            if (path) return enforce(e, decideFileAccess("read", path, policy, tctx), [path])
            return
          }
          case "write":
          case "edit": {
            const path = str(input.path)
            if (path) return enforce(e, decideFileAccess("write", path, policy, tctx), [path])
            return
          }
          case "patch": {
            const paths = patchPaths(str(input.patchText) ?? "")
            const decisions = paths.map((p) => decideFileAccess("write", p, policy, tctx))
            const merged: Decision = {
              effect: decisions.reduce((a, d) => strongest(a, d.effect), "allow" as Decision["effect"]),
              findings: decisions.flatMap((d) => d.findings),
              reason: decisions.map((d) => d.reason).filter(Boolean).join("\n") || undefined,
            }
            return enforce(e, merged, paths)
          }
          case "webfetch": {
            const url = str(input.url)
            if (!url) return
            await enforce(e, await withRecall(decideFetch(url, policy, tctx), fetchKeys(url), e.tool, e.sessionID, url), [url])
            checkedFetch.add(`${e.sessionID}|${url}`)
            return
          }
          default: {
            if (taint.isUntrustedTool(e.tool) && !["websearch"].includes(e.tool)) {
              const recalled = await withRecall({ effect: "allow", findings: [] }, [`tool:${e.tool}`], e.tool, e.sessionID, e.tool)
              if (recalled.effect !== "allow") return enforce(e, recalled, [e.tool])
            }
            audit.append({ kind: "tool", sessionID: e.sessionID, tool: e.tool, input: redactDeep(input) })
          }
        }
      })

      // Third-party tools after taint: an injected prompt's best exfil channel is another integration.
      await ctx.permission.hook("evaluate", async (e) => {
        // fetch() inside Code Mode's `execute` reaches the network through this webfetch check, not through
        // the webfetch tool, so apply the same URL policy, threat memory and taint here.
        if (e.action === "webfetch") {
          for (const url of e.resources) {
            if (checkedFetch.delete(`${e.sessionID}|${url}`)) continue
            const decision = await withRecall(decideFetch(url, policy, { tainted: taint.isTainted(e.sessionID) }), fetchKeys(url), "execute", e.sessionID, url)
            audit.append({ kind: "decision", sessionID: e.sessionID, tool: "execute", effect: decision.effect, resources: [url], findings: decision.findings.map((f) => f.rule), tainted: taint.isTainted(e.sessionID) })
            if (decision.effect === "deny") {
              e.effect = "deny"
              e.message = `[komainu] Blocked: ${decision.reason ?? "fetch blocked by policy"}`
              notify(e.sessionID, `⛩ Blocked fetch in code: ${decision.findings[0]?.message ?? url}`)
              return
            }
            if (decision.effect === "ask" && e.effect === "allow") {
              e.effect = "ask"
              e.message = decision.reason
            }
            taint.mark(e.sessionID, { tool: "execute", detail: url, suspicious: [] })
          }
        }
        if (forceAsk.has(`${e.sessionID}|${e.action}`) && e.effect === "allow") e.effect = "ask"
        if (e.effect === "allow" && taint.isTainted(e.sessionID) && taint.isUntrustedTool(e.action) && !["webfetch", "websearch"].includes(e.action)) {
          e.effect = "ask"
          e.message = "[komainu] This session has read untrusted external content; confirm this third-party tool call."
        }
      })

      // ---------------------------------------------------------------- right-size effort (0 tokens)
      // Runs after you send a prompt and before the model sees it. Silent when the effort fits;
      // otherwise asks the TUI (ADVISOR_RPC) and waits. One decision per prompt, reused for its later steps.
      const configuredEffort = (opts.effort as string) === "ask" ? "suggest" : (opts.effort ?? "suggest")
      const decided = new Map<string, Promise<string | undefined>>()
      const waiting = new Map<string, (choice: AdvisorChoice) => void>()
      let variants: Map<string, string[]> | undefined
      const variantsOf = async (providerID: string, modelID: string) => {
        variants ??= new Map((await ctx.model.list()).data.map((m) => [`${m.providerID}/${m.id}`, m.variants.map((v) => v.id)]))
        return variants.get(`${providerID}/${modelID}`) ?? []
      }
      const imageWaiting = new Map<string, (choice: ImageChoice) => void>()
      const advisor = await ctx.rpc.register(ADVISOR_RPC, {
        imageAnswer: async (input) => {
          const a = input as { id: string; choice: ImageChoice }
          const ok = imageWaiting.has(a.id)
          imageWaiting.get(a.id)?.(a.choice)
          return { ok }
        },
        answer: async (input) => {
          const a = input as { id: string; choice: AdvisorChoice }
          waiting.get(a.id)?.(a.choice)
          return { ok: waiting.has(a.id) }
        },
      })
      notify = (sessionID, message) => void advisor.events.emit("notice", { sessionID, message } as never).catch(() => undefined)
      const ask = (q: AdvisorQuestion) =>
        new Promise<AdvisorChoice>((resolve) => {
          const done = (choice: AdvisorChoice) => {
            clearTimeout(timer)
            waiting.delete(q.id)
            resolve(choice)
          }
          const timer = setTimeout(() => done("keep"), ADVISOR_TIMEOUT_MS)
          waiting.set(q.id, done)
          advisor.events.emit("question", q as never).catch(() => done("keep"))
        })

      const decide = async (mode: "suggest" | "auto", sessionID: string, text: string, model: { providerID: string; id: string; variant?: string }) => {
        const d = decideEffort(assessPrompt(text), model.variant, await variantsOf(model.providerID, model.id), { mode })
        const base = { kind: "effort", sessionID, mode, model: `${model.providerID}/${model.id}`, selected: model.variant ?? "default", level: d.assessment.level, confidence: d.assessment.confidence }
        if (!d.target || !d.suggestion) {
          audit.append({ ...base, outcome: "fits" })
          return undefined
        }
        if (d.action === "lower") {
          audit.append({ ...base, outcome: "auto-lowered", used: d.target })
          return d.target
        }
        const choice = await ask({
          id: randomUUID(), sessionID, directory: workspace, current: model.variant ?? "default", target: d.target,
          direction: d.suggestion, level: d.assessment.level, reasons: [...d.assessment.reasons],
        })
        if (choice === "auto") writeSettings((s) => ({ ...s, effort: "auto" }))
        audit.append({ ...base, outcome: `asked:${choice}`, offered: d.target })
        return choice === "keep" ? undefined : d.target
      }

      // ---------------------------------------------------------------- image guard
      // Attached images are checked once per prompt, before the model sees them. Flagged → you decide; cancelling
      // stops the prompt. Sending anyway marks the session untrusted, so later risky actions need approval.
      const imageMode = () => settings().images?.mode ?? opts.imageGuard ?? "ask"
      const imageSrt = srtBinary()
      const scanned = new Map<string, Promise<ImageVerdict>>()
      const guarded = new Map<string, Promise<void>>()
      let ocrNoticeShown = false
      const askImage = (a: ImageAlert) =>
        new Promise<ImageChoice>((resolve) => {
          const done = (choice: ImageChoice) => {
            clearTimeout(timer)
            imageWaiting.delete(a.id)
            resolve(choice)
          }
          const timer = setTimeout(() => done("cancel"), ADVISOR_TIMEOUT_MS * 2) // unanswered → not sent
          imageWaiting.set(a.id, done)
          advisor.events.emit("image", a as never).catch(() => done("cancel"))
        })

      const guardImages = async (sessionID: string, files: ReadonlyArray<{ data: string; mime: string; name?: string }>) => {
        const mode = imageMode()
        for (const [i, f] of files.entries()) {
          const bytes = Buffer.from(f.data, "base64")
          const name = f.name || `image ${i + 1}`
          const sha = createHash("sha256").update(bytes).digest("hex")
          const known = memoryOn() ? memory.lookup(`image:${sha}`) : undefined
          let verdict = scanned.get(sha)
          if (!verdict) {
            if (!known && opts.imageOcr !== false && imageSrt) notify(sessionID, `⛩ Image guard: checking ${name}…`)
            verdict = scanImage(bytes, f.mime, { srt: imageSrt, ocr: !known && opts.imageOcr !== false })
            scanned.set(sha, verdict)
          }
          const v = await verdict
          const findings = known ? [{ rule: "memory/flagged-image", severity: "high" as const, message: describeIncident(known, workspace) }, ...v.findings] : [...v.findings]
          const base = { kind: "image", sessionID, name, sha256: sha, type: v.type, size: v.bytes, ocr: v.ocr, findings: findings.map((x) => x.rule) }
          const ocrNote = describeOcrStatus(v.ocr)
          if (ocrNote && !ocrNoticeShown && v.ocr !== "skipped") {
            ocrNoticeShown = true
            notify(sessionID, `⛩ Image guard: ${ocrNote}`)
          }
          if (!known && v.verdict === "clean") {
            audit.append({ ...base, decision: "clean" })
            continue
          }
          const choice: ImageChoice | "blocked" =
            mode === "block" ? "blocked" : await askImage({ id: randomUUID(), sessionID, directory: workspace, name, findings, text: v.readableText, remembered: !!known })
          remember(`image:${sha}`, findings.filter((x) => !x.rule.startsWith("memory/")).map((x) => x.rule))
          if (choice === "send") {
            taint.mark(sessionID, { tool: "image", detail: name, suspicious: findings })
            audit.append({ ...base, decision: "sent" })
            continue
          }
          audit.append({ ...base, decision: choice === "blocked" ? "blocked" : "cancelled" })
          throw new Error(
            `[komainu] Image guard: "${name}" was not sent — ${findings[0]?.message ?? "it looks poisoned"}. ` +
              (choice === "blocked" ? "Image guard is set to block (/komainu → Image guard)." : "You chose not to send it."),
          )
        }
      }

      await ctx.session.hook("experimental.model.resolve", async (e) => {
        if (e.kind !== "primary") return
        const imagesOn = imageMode() !== "off"
        const mode = settings().effort ?? configuredEffort
        if (!imagesOn && mode === "off") return
        const user = [...(await ctx.session.context({ sessionID: e.sessionID }))].reverse().find((m) => m.type === "user")
        if (!user || user.type !== "user") return
        const key = `${e.sessionID}|${user.id}`
        const images = (user.files ?? []).filter((f) => f.mime.startsWith("image/") || sniffType(Buffer.from(f.data.slice(0, 2048), "base64")) !== "unknown")
        if (imagesOn && images.length) {
          let check = guarded.get(key)
          if (!check) {
            check = guardImages(e.sessionID, images)
            guarded.set(key, check)
          }
          await check // throws when the image isn't sent: the prompt stops here
        }
        if (mode === "off") return
        let choice = decided.get(key)
        if (!choice) {
          choice = decide(mode, e.sessionID, user.text, e.model).catch(() => undefined)
          decided.set(key, choice)
        }
        const variant = await choice
        if (variant && variant !== e.model.variant) e.model = { ...e.model, variant: variant as typeof e.model.variant }
      })

      // ---------------------------------------------------------------- contain
      if (srt && srtSettings) {
        await ctx.shell.hook("create.before", (e) => {
          if (!isWrapped(e.command, srt)) e.command = wrapCommand(e.command, srtSettings, srt)
        })
      }

      // ---------------------------------------------------------------- detect + correct
      await ctx.tool.hook("execute.after", async (e) => {
        if (e.status !== "completed") {
          audit.append({ kind: "tool-error", sessionID: e.sessionID, tool: e.tool, error: String(e.error.message ?? "") })
          return
        }
        let content = e.result.content as Content | undefined
        const redactions: string[] = []
        content = mapText(content, (t) => {
          const r = redact(t)
          redactions.push(...r.redactions.map((x) => x.id))
          return r.text
        })

        if (taint.isUntrustedTool(e.tool)) {
          const text = typeof content === "string" ? content : (content ?? []).map((c) => c.text ?? "").join("\n")
          const suspicious = scanForInjection(text)
          const input = (e.input ?? {}) as Input
          const detail = str(input.url) ?? str(input.query) ?? e.tool
          taint.mark(e.sessionID, { tool: e.tool, detail, suspicious })
          audit.append({ kind: "taint", sessionID: e.sessionID, tool: e.tool, detail, suspicious: suspicious.map((f) => f.rule) })
          const key = sourceKey(e.tool, detail)
          if (key && suspicious.length) remember(key, suspicious.map((f) => f.rule))
          if (suspicious.length) notify(e.sessionID, `⛩ Possible prompt injection in ${detail.length > 60 ? detail.slice(0, 59) + "…" : detail}. Risky actions in this session now need your approval.`)
          if (opts.fenceUntrusted !== false) content = mapText(content, (t) => fence(detail, t, suspicious))
        }

        if (["write", "edit", "patch"].includes(e.tool) && opts.scan?.builtin !== false) {
          const input = (e.input ?? {}) as Input
          const paths = e.tool === "patch" ? patchPaths(str(input.patchText) ?? "") : [str(input.path)].filter((p): p is string => !!p)
          const findings: Finding[] = []
          for (const p of paths) {
            const abs = resolvePath(p, workspace)
            if (!existsSync(abs)) continue
            findings.push(...scanSource(p, readFileSync(abs, "utf8")))
            if (opts.scan?.semgrep) findings.push(...(await scanWithSemgrep(abs, { semgrepConfig: typeof opts.scan.semgrep === "string" ? opts.scan.semgrep : undefined })))
          }
          if (findings.length) {
            content = appendText(content, formatFindingsForModel(findings))
            audit.append({ kind: "scan", sessionID: e.sessionID, tool: e.tool, findings: findings.map((f) => `${f.file}:${f.line} ${f.rule}`) })
          }
        }

        if (redactions.length) audit.append({ kind: "redact", sessionID: e.sessionID, tool: e.tool, redactions })
        e.result = { ...e.result, content: content as never, ...(e.result.output === undefined ? {} : { output: redactDeep(e.result.output) }) }
      })

      return async () => {
        audit.append({ kind: "stop" })
        await sink?.close().catch(() => undefined)
      }
    },
  }
  return plugin
}

export default createKomainu()
