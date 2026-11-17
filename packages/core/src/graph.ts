/**
 * Security pipeline graph: turns the hash-chained audit log into
 *   Source → Session → Action → Layer → Outcome
 * so you can see what entered the agent's context, what it tried, which layer caught it and what happened.
 * Pure functions, no dependencies: the HTML view and the optional Neo4j sink share `classify`.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"
import { verifyAuditLog, type AuditEntry } from "./audit.js"
import { commandHosts, hostOf, sourceScope } from "./memory.js"

export type Column = "source" | "session" | "action" | "layer" | "outcome"
export type StepSeverity = "ok" | "warn" | "bad"

export interface Step {
  readonly seq: number
  readonly ts: string
  readonly hash: string
  readonly kind: string
  readonly sessionID?: string
  readonly source?: string
  readonly action: string
  readonly layer: string
  readonly outcome: string
  readonly severity: StepSeverity
  readonly detail: string
  /** network hosts this step touched or tried to touch */
  readonly targets: readonly string[]
  /** node ids this step passes through (filled by auditToGraph) */
  readonly path?: readonly string[]
}

export interface GraphNode {
  readonly id: string
  readonly column: Column
  readonly label: string
  readonly severity: StepSeverity
  readonly count: number
}

export interface GraphEdge {
  readonly from: string
  readonly to: string
  readonly severity: StepSeverity
  readonly count: number
  readonly steps: readonly number[]
}

export interface SecurityGraph {
  readonly workspace?: string
  readonly nodes: readonly GraphNode[]
  readonly edges: readonly GraphEdge[]
  readonly steps: readonly Step[]
  readonly stats: Readonly<Record<string, number>>
}

const short = (s: string, n = 64) => (s.length > n ? s.slice(0, n - 1) + "…" : s)
const sevRank: Record<StepSeverity, number> = { ok: 0, warn: 1, bad: 2 }
const worst = (a: StepSeverity, b: StepSeverity): StepSeverity => (sevRank[a] >= sevRank[b] ? a : b)
const list = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : [])
const firstString = (v: unknown) => list(v)[0] ?? ""

/** One audit entry → one pipeline step (or undefined for bookkeeping entries like start/stop/effort). */
export function classify(entry: AuditEntry): Step | undefined {
  const e = entry.event as Record<string, any>
  const base = { seq: entry.seq, ts: entry.ts, hash: entry.hash, kind: String(e.kind), sessionID: e.sessionID as string | undefined }
  const tool = String(e.tool ?? "")
  switch (e.kind) {
    case "taint": {
      const detail = String(e.detail ?? tool)
      const rules = list(e.suspicious)
      const host = hostOf(detail)
      const scope = sourceScope(detail)
      return {
        ...base, source: scope ? `web: ${scope}` : `tool: ${tool}`, action: `${tool} → model context`, layer: "Taint tracking",
        outcome: rules.length ? "flagged + fenced" : "fenced as untrusted", severity: rules.length ? "bad" : "warn",
        detail: rules.length ? `${short(detail)} — ${rules.join(", ")}` : short(detail), targets: host ? [host] : [],
      }
    }
    case "decision": {
      const effect = String(e.effect)
      const findings = list(e.findings)
      const resource = firstString(e.resources)
      const memory = findings.some((f) => f.startsWith("memory/"))
      // hard blocks are the policy engine's call; an ask in a tainted session is taint tracking raising the bar
      const layer = memory ? "Threat memory" : e.tainted && effect === "ask" ? "Taint tracking" : "Policy engine"
      const targets = tool === "shell" ? commandHosts(resource) : tool === "webfetch" ? [hostOf(resource)].filter((h): h is string => !!h) : []
      return {
        ...base, action: effect === "allow" ? `${tool} (routine)` : `${tool}: ${short(resource, 48)}`, layer,
        outcome: effect === "allow" ? "allowed" : effect === "ask" ? "asked you" : "blocked",
        severity: effect === "deny" ? "bad" : effect === "ask" ? "warn" : "ok",
        detail: [short(resource, 160), findings.join(", ")].filter(Boolean).join(" — "), targets,
      }
    }
    case "reply": {
      const resource = firstString(e.resources)
      const approved = e.reply === "approved"
      return {
        ...base, action: `${tool}: ${short(resource, 48)}`, layer: "You", outcome: approved ? "you approved" : "you denied",
        severity: approved ? "warn" : "bad", detail: short(resource, 160), targets: tool === "shell" ? commandHosts(resource) : [],
      }
    }
    case "recall":
      return {
        ...base, source: e.key ? `memory: ${String(e.key)}` : undefined, action: `${tool}: ${short(String(e.resource ?? ""), 48)}`,
        layer: "Threat memory", outcome: "recognised from memory", severity: "bad", detail: String(e.summary ?? ""), targets: [],
      }
    case "image": {
      const decision = String(e.decision)
      const outcome = decision === "clean" ? "allowed" : decision === "sent" ? "sent anyway (session untrusted)" : decision === "blocked" ? "blocked" : "you cancelled"
      return {
        ...base, source: `image: ${String(e.name ?? "image")}`, action: "image → model context", layer: "Image guard", outcome,
        severity: decision === "clean" ? "ok" : "bad", detail: [String(e.name ?? ""), list(e.findings).join(", ")].filter(Boolean).join(" — "), targets: [],
      }
    }
    case "scan":
      return {
        ...base, action: `${tool} (code written)`, layer: "Code scanner", outcome: "findings sent back to model", severity: "warn",
        detail: list(e.findings).join(", "), targets: [],
      }
    case "redact":
      return {
        ...base, action: `${tool} output`, layer: "Secret redaction", outcome: "secrets redacted", severity: "warn",
        detail: list(e.redactions).join(", "), targets: [],
      }
    case "tool":
      return { ...base, action: `${tool} (routine)`, layer: "Policy engine", outcome: "allowed", severity: "ok", detail: tool, targets: [] }
    default:
      return undefined
  }
}

export function readAuditEntries(path: string): AuditEntry[] {
  try {
    return readFileSync(path, "utf8").split("\n").filter(Boolean).flatMap((l) => {
      try {
        return [JSON.parse(l) as AuditEntry]
      } catch {
        return []
      }
    })
  } catch {
    return []
  }
}

export function auditToGraph(entries: readonly AuditEntry[]): SecurityGraph {
  const nodes = new Map<string, GraphNode>()
  const edges = new Map<string, GraphEdge>()
  const steps: Step[] = []
  let workspace: string | undefined

  const node = (column: Column, label: string, severity: StepSeverity) => {
    const id = `${column}:${label}`
    const prev = nodes.get(id)
    nodes.set(id, { id, column, label, severity: prev ? worst(prev.severity, severity) : severity, count: (prev?.count ?? 0) + 1 })
    return id
  }
  const edge = (from: string, to: string, severity: StepSeverity, seq: number) => {
    const id = `${from}→${to}`
    const prev = edges.get(id)
    edges.set(id, {
      from, to, severity: prev ? worst(prev.severity, severity) : severity, count: (prev?.count ?? 0) + 1,
      steps: prev ? (prev.steps.length < 200 ? [...prev.steps, seq] : prev.steps) : [seq],
    })
  }

  for (const entry of entries) {
    const ev = entry.event as Record<string, unknown>
    if (ev.kind === "start" && typeof ev.workspace === "string") workspace = ev.workspace
    const step = classify(entry)
    if (!step) continue
    const sid = step.sessionID ? `session ${step.sessionID.slice(-8)}` : "no session"
    const session = node("session", sid, step.severity)
    if (step.source) edge(node("source", step.source, step.severity), session, step.severity, step.seq)
    const action = node("action", step.action, step.severity)
    const layer = node("layer", step.layer, step.severity)
    const outcome = node("outcome", step.outcome, step.severity)
    edge(session, action, step.severity, step.seq)
    edge(action, layer, step.severity, step.seq)
    edge(layer, outcome, step.severity, step.seq)
    steps.push({ ...step, path: [step.source ? `source:${step.source}` : "", session, action, layer, outcome].filter(Boolean) })
  }

  const count = (f: (s: Step) => boolean) => steps.filter(f).length
  return {
    workspace,
    nodes: [...nodes.values()],
    edges: [...edges.values()],
    steps,
    stats: {
      steps: steps.length,
      blocked: count((s) => s.outcome === "blocked" || s.outcome === "you cancelled"),
      asked: count((s) => s.outcome === "asked you"),
      denied: count((s) => s.outcome === "you denied"),
      tainted: count((s) => s.kind === "taint"),
      flagged: count((s) => s.outcome === "flagged + fenced"),
      redacted: count((s) => s.kind === "redact"),
      recalled: count((s) => s.kind === "recall"),
    },
  }
}

// ---------------------------------------------------------------- HTML (self-contained, no network)

export function renderGraphHtml(graph: SecurityGraph, opts: { title?: string; chain?: { ok: boolean; detail: string } } = {}): string {
  const data = JSON.stringify({ graph, chain: opts.chain ?? null }).replace(/</g, "\\u003c").replace(/[\u2028\u2029]/g, " ")
  const title = (opts.title ?? "Komainu security graph").replace(/[<>&"]/g, "")
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>${title}</title>
<style>
:root{--bg:#0e1014;--panel:#161a21;--line:#2a303b;--text:#e6e9ef;--muted:#8a93a3;--ok:#4a9d6e;--warn:#e0a63a;--bad:#e5534b;--accent:#d4a24c}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
header{display:flex;flex-wrap:wrap;align-items:baseline;gap:8px 24px;padding:18px 24px;border-bottom:1px solid var(--line)}
h1{font-size:18px;margin:0;font-weight:600}h1 span{color:var(--accent)}.sub{color:var(--muted);font-size:13px}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-left:auto}.stat{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:4px 10px;font-size:12px;color:var(--muted)}
.stat b{color:var(--text);font-size:14px;margin-right:4px}.stat.bad b{color:var(--bad)}.stat.warn b{color:var(--warn)}.stat.ok b{color:var(--ok)}
#wrap{overflow:auto;padding:8px 12px}svg{display:block}text{fill:var(--text);font-size:12px}
.col{fill:var(--muted);font-size:11px;letter-spacing:.08em;text-transform:uppercase}
.node rect{fill:var(--panel);stroke:var(--line);stroke-width:1;rx:6}.node{cursor:pointer}.node:hover rect{stroke:var(--accent)}
.node .bar{stroke:none}.node.dim,.edge.dim{opacity:.12}.edge{fill:none;stroke-linecap:round}
.cnt{fill:var(--muted);font-size:11px}
#steps{padding:0 24px 32px}table{width:100%;border-collapse:collapse;font-size:12.5px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500}td.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:var(--muted);word-break:break-all}
.pill{display:inline-block;border-radius:999px;padding:1px 8px;font-size:11px;border:1px solid currentColor}.pill.ok{color:var(--ok)}.pill.warn{color:var(--warn)}.pill.bad{color:var(--bad)}
.hint{color:var(--muted);font-size:12px;padding:0 24px 8px}button{background:var(--panel);color:var(--text);border:1px solid var(--line);border-radius:6px;padding:3px 10px;cursor:pointer;font:inherit;font-size:12px}
.empty{padding:48px 24px;color:var(--muted)}
</style></head><body>
<header><h1><span>⛩</span> Komainu security pipeline</h1><div class="sub" id="sub"></div><div class="stats" id="stats"></div></header>
<div class="hint">Click a node to trace its paths. <button id="reset">Show all</button> <label><input type="checkbox" id="routine"> include routine allowed actions</label></div>
<div id="wrap"></div><div id="steps"></div>
<script>
const {graph:G,chain}=${data};
const COLS=[["source","Untrusted input"],["session","Session"],["action","What the agent tried"],["layer","Caught by"],["outcome","Result"]];
const C={ok:getComputedStyle(document.documentElement).getPropertyValue('--ok'),warn:getComputedStyle(document.documentElement).getPropertyValue('--warn'),bad:getComputedStyle(document.documentElement).getPropertyValue('--bad')};
const $=s=>document.querySelector(s),el=(t,a={},...k)=>{const e=document.createElementNS('http://www.w3.org/2000/svg',t);for(const x in a)e.setAttribute(x,a[x]);k.forEach(c=>e.append(c));return e};
const esc=s=>String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
$('#sub').textContent=(G.workspace||'')+' · '+G.steps.length+' recorded steps'+(chain?(' · audit chain '+(chain.ok?'verified ✓':'BROKEN ✗ '+chain.detail)):'');
const S=G.stats,stat=(k,l,c)=>'<div class="stat '+c+'"><b>'+(S[k]||0)+'</b>'+l+'</div>';
$('#stats').innerHTML=stat('blocked','blocked','bad')+stat('denied','denied by you','bad')+stat('asked','asked you','warn')+stat('flagged','injections flagged','bad')+stat('tainted','untrusted inputs','warn')+stat('redacted','redactions','warn')+stat('recalled','remembered threats','warn');
let routine=false,focus=(location.hash.startsWith('#focus=')?decodeURIComponent(location.hash.slice(7)):null);
function visible(){const keep=new Set(),es=G.edges.filter(e=>routine||e.severity!=='ok');es.forEach(e=>{keep.add(e.from);keep.add(e.to)});return{ns:G.nodes.filter(n=>keep.has(n.id)),es}}
function draw(){
 const {ns,es}=visible(),wrap=$('#wrap');wrap.innerHTML='';
 if(!ns.length){wrap.innerHTML='<div class="empty">Nothing caught yet'+(routine?'':' (routine allowed actions hidden)')+'. Komainu records every decision in .komainu/audit.jsonl; this graph fills in as it works.</div>';table([]);return}
 const W=Math.max(1100,wrap.clientWidth-24),colW=W/COLS.length,nw=Math.min(210,colW-36),nh=34,gap=10,pos={};
 let H=0;COLS.forEach(([c],i)=>{const col=ns.filter(n=>n.column===c).sort((a,b)=>({bad:0,warn:1,ok:2}[a.severity]-{bad:0,warn:1,ok:2}[b.severity])||b.count-a.count);col.forEach((n,j)=>pos[n.id]={x:i*colW+18,y:44+j*(nh+gap)});H=Math.max(H,44+col.length*(nh+gap))});
 const svg=el('svg',{width:W,height:H+10});
 COLS.forEach(([c,l],i)=>svg.append(el('text',{class:'col',x:i*colW+18,y:22},l)));
 const hit=s=>!focus||(s.path||[]).includes(focus),shown=G.steps.filter(hit),related=new Set(shown.flatMap(s=>s.path||[]));
 const on=id=>!focus||related.has(id);
 const maxc=Math.max(...es.map(e=>e.count));
 es.forEach(e=>{const a=pos[e.from],b=pos[e.to];if(!a||!b)return;const x1=a.x+nw,y1=a.y+nh/2,x2=b.x,y2=b.y+nh/2,mx=(x1+x2)/2;
  const p=el('path',{class:'edge'+(on(e.from)&&on(e.to)?'':' dim'),d:'M'+x1+','+y1+' C'+mx+','+y1+' '+mx+','+y2+' '+x2+','+y2,stroke:C[e.severity],'stroke-width':1.5+4*Math.log1p(e.count)/Math.log1p(maxc),'stroke-opacity':.75});
  p.append(el('title',{},e.count+' step(s)'));svg.append(p)});
 ns.forEach(n=>{const p=pos[n.id],g=el('g',{class:'node'+(on(n.id)?'':' dim'),transform:'translate('+p.x+','+p.y+')'});
  g.append(el('rect',{width:nw,height:nh,rx:6}),el('rect',{class:'bar',width:4,height:nh,fill:C[n.severity],rx:2}));
  const t=el('text',{x:12,y:21});t.textContent=n.label.length>26?n.label.slice(0,25)+'…':n.label;g.append(t);
  const c=el('text',{class:'cnt',x:nw-8,y:21,'text-anchor':'end'});c.textContent=n.count>1?'×'+n.count:'';g.append(c);
  g.append(el('title',{},n.label));g.onclick=()=>{focus=focus===n.id?null:n.id;draw()};svg.append(g)});
 wrap.append(svg);
 table(shown.filter(s=>routine||s.severity!=='ok'||focus));
}
function table(rows){$('#steps').innerHTML=rows.length?'<table><tr><th>#</th><th>Time</th><th>Action</th><th>Caught by</th><th>Result</th><th>Detail</th></tr>'+rows.slice(-400).reverse().map(s=>'<tr><td>'+s.seq+'</td><td>'+esc(s.ts.slice(11,19))+'</td><td>'+esc(s.action)+'</td><td>'+esc(s.layer)+'</td><td><span class="pill '+s.severity+'">'+esc(s.outcome)+'</span></td><td class="mono">'+esc(s.detail)+'</td></tr>').join('')+'</table>':''}
$('#reset').onclick=()=>{focus=null;draw()};$('#routine').onchange=e=>{routine=e.target.checked;draw()};addEventListener('resize',draw);draw();
</script></body></html>
`
}

/** Builds `<stateDir>/graph.html` from `<stateDir>/audit.jsonl` and returns its path. */
export function writeSecurityGraph(workspace: string, stateDir = join(workspace, ".komainu")): { path: string; graph: SecurityGraph } {
  const auditPath = join(stateDir, "audit.jsonl")
  const graph = auditToGraph(readAuditEntries(auditPath))
  const v = existsSync(auditPath) ? verifyAuditLog(auditPath) : undefined
  const chain = v ? (v.ok ? { ok: true, detail: `${v.entries} entries` } : { ok: false, detail: `at entry ${v.brokenAt}: ${v.reason}` }) : undefined
  const path = join(stateDir, "graph.html")
  mkdirSync(stateDir, { recursive: true })
  writeFileSync(path, renderGraphHtml(graph, { chain }), { mode: 0o600 })
  return { path, graph }
}
