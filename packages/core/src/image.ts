/**
 * Image guard: checks images before a model sees them.
 *
 * Images can carry prompt injections the user never notices:
 *   - faint or tiny text a model reads but a person skims past
 *   - text that only appears after the image is downscaled (image-scaling attacks: models see a resized copy)
 *   - instructions in metadata, scripts in SVGs, extra files appended after the image data (polyglots)
 *   - malformed files aimed at image decoders, and "decompression bombs"
 *
 * Structural checks are pure TypeScript and never decode pixels. Text recognition (optional: Tesseract, plus
 * ImageMagick for the resized/contrast passes) decodes the untrusted file, so it only runs inside the OS sandbox
 * with no network. Without `srt` it is skipped and the verdict says so.
 */
import { execFile } from "node:child_process"
import { createHash } from "node:crypto"
import { mkdtempSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { inflateSync } from "node:zlib"
import { scanForInjection } from "./taint.js"
import { shellQuote, writeSrtSettings } from "./sandbox.js"
import type { Finding } from "./types.js"

export type ImageType = "png" | "jpeg" | "gif" | "webp" | "bmp" | "svg" | "unknown"

export interface ImageInspection {
  readonly type: ImageType
  readonly width?: number
  readonly height?: number
  readonly sha256: string
  readonly bytes: number
  readonly findings: readonly Finding[]
  /** text found in metadata / SVG text nodes */
  readonly embeddedText: readonly string[]
}

export interface OcrPass {
  readonly name: string
  readonly text: string
}

export type OcrStatus = "ok" | "no-tesseract" | "no-sandbox" | "skipped" | "failed"

export interface ImageVerdict extends ImageInspection {
  readonly verdict: "clean" | "suspicious"
  readonly ocr: OcrStatus
  /** What the model may read (OCR text, deduplicated), for showing the user. */
  readonly readableText: string
}

/** Above this many pixels we don't decode at all. Real screenshots are far below it. */
export const MAX_PIXELS = 60_000_000
const MAX_SIDE = 30_000

const MIME: Record<Exclude<ImageType, "unknown">, string[]> = {
  png: ["image/png", "image/apng"],
  jpeg: ["image/jpeg", "image/jpg", "image/pjpeg"],
  gif: ["image/gif"],
  webp: ["image/webp"],
  bmp: ["image/bmp", "image/x-ms-bmp"],
  svg: ["image/svg+xml"],
}

const u16be = (b: Uint8Array, o: number) => (b[o]! << 8) | b[o + 1]!
const u32be = (b: Uint8Array, o: number) => ((b[o]! << 24) >>> 0) + (b[o + 1]! << 16) + (b[o + 2]! << 8) + b[o + 3]!
const u16le = (b: Uint8Array, o: number) => b[o]! | (b[o + 1]! << 8)
const u24le = (b: Uint8Array, o: number) => b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16)
const u32le = (b: Uint8Array, o: number) => (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0
const ascii = (b: Uint8Array, o: number, n: number) => String.fromCharCode(...b.subarray(o, o + n))
const latin1 = (b: Uint8Array) => Buffer.from(b).toString("latin1")
const utf8 = (b: Uint8Array) => Buffer.from(b).toString("utf8")

export function sniffType(b: Uint8Array): ImageType {
  if (b.length >= 8 && b[0] === 0x89 && ascii(b, 1, 3) === "PNG") return "png"
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpeg"
  if (b.length >= 6 && ascii(b, 0, 4) === "GIF8") return "gif"
  if (b.length >= 12 && ascii(b, 0, 4) === "RIFF" && ascii(b, 8, 4) === "WEBP") return "webp"
  if (b.length >= 26 && ascii(b, 0, 2) === "BM") return "bmp"
  const head = utf8(b.subarray(0, 1024)).replace(/^﻿/, "").trimStart().toLowerCase()
  if (head.startsWith("<svg") || (head.startsWith("<?xml") && head.includes("<svg")) || (head.startsWith("<!doctype svg"))) return "svg"
  return "unknown"
}

/** Printable runs inside binary metadata (EXIF, XMP, comments). */
function printableRuns(b: Uint8Array, min = 12): string[] {
  return [...latin1(b).matchAll(new RegExp(`[\\x20-\\x7e\\t]{${min},}`, "g"))].map((m) => m[0].trim()).filter(Boolean)
}

const EMBEDDED_SIGNATURES: ReadonlyArray<[string, RegExp]> = [
  ["zip archive", /PK\x03\x04/],
  ["PDF document", /%PDF-/],
  ["HTML/script", /<(?:script|html|iframe)\b/i],
  ["shell script", /#!\/(?:bin|usr)\//],
  ["Windows executable", /MZ[\s\S]{58}PE\0\0/],
  ["ELF executable", /\x7fELF/],
]

interface Parsed {
  width?: number
  height?: number
  end?: number // offset where the image format says the data ends
  text: string[]
  problems: Finding[]
}

function parsePng(b: Uint8Array): Parsed {
  const out: Parsed = { text: [], problems: [] }
  let o = 8
  while (o + 8 <= b.length) {
    const len = u32be(b, o)
    const type = ascii(b, o + 4, 4)
    const data = b.subarray(o + 8, Math.min(b.length, o + 8 + len))
    if (type === "IHDR" && data.length >= 8) {
      out.width = u32be(data, 0)
      out.height = u32be(data, 4)
    } else if (type === "tEXt") {
      const z = data.indexOf(0)
      out.text.push(latin1(data.subarray(z + 1)))
    } else if (type === "zTXt" || type === "iTXt") {
      try {
        const z = data.indexOf(0)
        if (type === "zTXt") out.text.push(latin1(inflateSync(data.subarray(z + 2), { maxOutputLength: 1 << 20 })))
        else {
          const compressed = data[z + 1] === 1
          let p = z + 3
          p = data.indexOf(0, p) + 1 // language tag
          p = data.indexOf(0, p) + 1 // translated keyword
          const body = data.subarray(p)
          out.text.push(utf8(compressed ? inflateSync(body, { maxOutputLength: 1 << 20 }) : body))
        }
      } catch {
        out.problems.push({ rule: "image/malformed", severity: "medium", message: `Corrupt ${type} metadata chunk` })
      }
    } else if (type === "eXIf") out.text.push(...printableRuns(data))
    o += 12 + len
    if (type === "IEND") {
      out.end = o
      break
    }
  }
  if (out.end === undefined) out.problems.push({ rule: "image/malformed", severity: "medium", message: "PNG has no end marker (truncated or malformed)" })
  return out
}

function parseJpeg(b: Uint8Array): Parsed {
  const out: Parsed = { text: [], problems: [] }
  let o = 2
  while (o + 4 <= b.length) {
    if (b[o] !== 0xff) break
    const marker = b[o + 1]!
    if (marker === 0xd8 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) {
      o += 2
      continue
    }
    const len = u16be(b, o + 2)
    const data = b.subarray(o + 4, Math.min(b.length, o + 2 + len))
    if (marker >= 0xc0 && marker <= 0xcf && ![0xc4, 0xc8, 0xcc].includes(marker) && data.length >= 5) {
      out.height = u16be(data, 1)
      out.width = u16be(data, 3)
    } else if (marker === 0xfe) out.text.push(latin1(data))
    else if (marker === 0xe1 || marker === 0xed || marker === 0xe2) out.text.push(...printableRuns(data))
    if (marker === 0xda) break // entropy-coded data follows
    o += 2 + len
  }
  // the last EOI marker ends the image (embedded EXIF thumbnails have their own, earlier one)
  for (let i = b.length - 2; i >= Math.max(2, b.length - 4_000_000); i--) {
    if (b[i] === 0xff && b[i + 1] === 0xd9) {
      out.end = i + 2
      break
    }
  }
  if (out.end === undefined) out.problems.push({ rule: "image/malformed", severity: "medium", message: "JPEG has no end marker (truncated or malformed)" })
  return out
}

function parseGif(b: Uint8Array): Parsed {
  const out: Parsed = { width: u16le(b, 6), height: u16le(b, 8), text: [], problems: [] }
  // comment extensions: 0x21 0xFE then sub-blocks
  for (let i = 13; i < b.length - 2; i++) {
    if (b[i] === 0x21 && b[i + 1] === 0xfe) {
      let p = i + 2
      let s = ""
      while (p < b.length && b[p]! > 0) {
        s += latin1(b.subarray(p + 1, p + 1 + b[p]!))
        p += 1 + b[p]!
      }
      if (s.length >= 4) out.text.push(s)
    }
  }
  return out
}

function parseWebp(b: Uint8Array): Parsed {
  const out: Parsed = { text: [], problems: [], end: 8 + u32le(b, 4) }
  let o = 12
  while (o + 8 <= Math.min(b.length, out.end!)) {
    const type = ascii(b, o, 4)
    const len = u32le(b, o + 4)
    const d = b.subarray(o + 8, o + 8 + len)
    if (type === "VP8X" && d.length >= 10) {
      out.width = u24le(d, 4) + 1
      out.height = u24le(d, 7) + 1
    } else if (type === "VP8 " && d.length >= 10 && out.width === undefined) {
      out.width = u16le(d, 6) & 0x3fff
      out.height = u16le(d, 8) & 0x3fff
    } else if (type === "VP8L" && d.length >= 5 && out.width === undefined) {
      const bits = u32le(d, 1)
      out.width = (bits & 0x3fff) + 1
      out.height = ((bits >> 14) & 0x3fff) + 1
    } else if (type === "EXIF" || type === "XMP ") out.text.push(...printableRuns(d))
    o += 8 + len + (len & 1)
  }
  return out
}

function parseBmp(b: Uint8Array): Parsed {
  return { width: Math.abs(u32le(b, 18) | 0), height: Math.abs(u32le(b, 22) | 0), end: u32le(b, 2), text: [], problems: [] }
}

function inspectSvg(text: string): { findings: Finding[]; text: string[] } {
  const findings: Finding[] = []
  if (/<script\b|\bon[a-z]+\s*=|javascript:/i.test(text)) findings.push({ rule: "image/svg-script", severity: "high", message: "SVG contains scripts or event handlers" })
  if (/<foreignObject\b/i.test(text)) findings.push({ rule: "image/svg-foreign-object", severity: "medium", message: "SVG embeds HTML (foreignObject)" })
  if (/\b(?:href|xlink:href|src)\s*=\s*["']\s*(?:https?:|\/\/|file:)/i.test(text) || /@import|url\(\s*["']?https?:/i.test(text))
    findings.push({ rule: "image/svg-external", severity: "medium", message: "SVG loads external resources" })
  const nodes = [...text.matchAll(/<(text|tspan|title|desc|metadata)\b[^>]*>([\s\S]*?)<\/\1>/gi)].map((m) => m[2]!.replace(/<[^>]+>/g, " ").trim())
  const comments = [...text.matchAll(/<!--([\s\S]*?)-->/g)].map((m) => m[1]!.trim())
  return { findings, text: [...nodes, ...comments].filter((t) => t.length >= 4) }
}

/** Structural checks only: never decodes pixels, safe to run on anything. */
export function inspectImage(bytes: Uint8Array, declaredMime?: string): ImageInspection {
  const sha256 = createHash("sha256").update(bytes).digest("hex")
  const type = sniffType(bytes)
  const findings: Finding[] = []
  const declared = declaredMime?.toLowerCase().split(";")[0]?.trim()
  if (type === "unknown") findings.push({ rule: "image/unknown-format", severity: "medium", message: `Not a recognised image format${declared ? ` (declared ${declared})` : ""}` })
  else if (declared && declared.startsWith("image/") && !MIME[type].includes(declared))
    findings.push({ rule: "image/type-mismatch", severity: "medium", message: `File is ${type.toUpperCase()} but was declared as ${declared}` })

  let parsed: Parsed = { text: [], problems: [] }
  let embeddedText: string[] = []
  try {
    if (type === "png") parsed = parsePng(bytes)
    else if (type === "jpeg") parsed = parseJpeg(bytes)
    else if (type === "gif") parsed = parseGif(bytes)
    else if (type === "webp") parsed = parseWebp(bytes)
    else if (type === "bmp") parsed = parseBmp(bytes)
  } catch {
    parsed.problems.push({ rule: "image/malformed", severity: "medium", message: "Image structure could not be parsed" })
  }
  findings.push(...parsed.problems)
  embeddedText = parsed.text.map((t) => t.replace(/\0/g, " ").trim()).filter((t) => t.length >= 4)

  if (type === "svg") {
    const svg = inspectSvg(utf8(bytes))
    findings.push(...svg.findings)
    embeddedText = svg.text
  }

  const { width, height } = parsed
  if (width !== undefined && height !== undefined) {
    if (width === 0 || height === 0) findings.push({ rule: "image/malformed", severity: "medium", message: "Image has zero width or height" })
    else if (width * height > MAX_PIXELS || width > MAX_SIDE || height > MAX_SIDE)
      findings.push({ rule: "image/bomb", severity: "high", message: `Image claims ${width}×${height} pixels (decompression bomb?); not decoded` })
  }

  if (parsed.end !== undefined && parsed.end < bytes.length) {
    const tail = bytes.subarray(parsed.end)
    const meaningful = tail.some((x) => x !== 0)
    if (meaningful && tail.length > 16) {
      const tailText = latin1(tail.subarray(0, 2_000_000))
      const hits = EMBEDDED_SIGNATURES.filter(([, r]) => r.test(tailText)).map(([n]) => n)
      findings.push(
        hits.length
          ? { rule: "image/polyglot", severity: "high", message: `Extra data after the image contains a hidden ${hits.join(", ")}` }
          : { rule: "image/trailing-data", severity: "medium", message: `${tail.length} bytes of extra data after the end of the image` },
      )
      embeddedText.push(...printableRuns(tail, 16).slice(0, 20))
    }
  }

  const metaInjection = scanForInjection(embeddedText.join("\n"))
  for (const f of metaInjection)
    findings.push({ rule: `image/metadata-${f.rule.replace("injection/", "")}`, severity: "high", message: `Hidden ${type === "svg" ? "SVG" : "metadata"} text looks like a prompt injection (${f.rule})` })

  return { type, width, height, sha256, bytes: bytes.length, findings, embeddedText }
}

// ---------------------------------------------------------------- text recognition (sandboxed)

export interface OcrOptions {
  /** `srt` binary. Without it, OCR is skipped unless `allowUnsandboxed`. */
  readonly srt?: string
  readonly allowUnsandboxed?: boolean
  readonly tesseract?: string
  readonly magick?: string
  readonly timeoutMs?: number
  /** Longest side models commonly downscale to; each is OCR'd with bicubic, bilinear and nearest filters. */
  readonly targetSizes?: readonly number[]
}

export function findImageTools() {
  const which = (n: string) => (typeof Bun !== "undefined" ? Bun.which(n) : undefined) ?? undefined
  return { tesseract: which("tesseract"), magick: which("magick") ?? which("convert") }
}

const EXT: Record<ImageType, string> = { png: "png", jpeg: "jpg", gif: "gif", webp: "webp", bmp: "bmp", svg: "svg", unknown: "bin" }

const run = (cmd: string, args: string[], timeout: number) =>
  new Promise<{ code: number; stdout: string; stderr: string }>((resolve) => {
    execFile(cmd, args, { timeout, maxBuffer: 8 << 20, killSignal: "SIGKILL" }, (err, stdout, stderr) =>
      resolve({ code: err ? ((err as { code?: number }).code ?? 1) : 0, stdout: String(stdout), stderr: String(stderr) }),
    )
  })

/** Recognises text in the image as a person sees it, contrast-boosted, and at downscaled sizes. Sandboxed, no network. */
export async function ocrImage(bytes: Uint8Array, type: ImageType, opts: OcrOptions = {}): Promise<{ status: OcrStatus; passes: OcrPass[] }> {
  const tools = findImageTools()
  const tesseract = opts.tesseract ?? tools.tesseract
  const magick = opts.magick ?? tools.magick
  if (!tesseract) return { status: "no-tesseract", passes: [] }
  if (!opts.srt && !opts.allowUnsandboxed) return { status: "no-sandbox", passes: [] }
  if (type === "unknown") return { status: "skipped", passes: [] }

  const dir = mkdtempSync(join(tmpdir(), "komainu-img-"))
  try {
    const input = join(dir, `in.${EXT[type]}`)
    writeFileSync(input, bytes)
    const q = shellQuote
    const src = `${q(input)}[0]` // first frame only
    const sizes = opts.targetSizes ?? [768]
    const variants: Array<[string, string]> = magick
      ? [
          ["as shown", `${q(magick)} ${src} -auto-orient -resize '2000x2000>' -colorspace Gray full.png`],
          ["contrast-boosted", `${q(magick)} ${src} -auto-orient -resize '2000x2000>' -colorspace Gray -negate -lat 25x25+1% -negate boost.png`],
          ...sizes.flatMap((s) =>
            ([["bicubic", "Catrom"], ["bilinear", "Triangle"], ["nearest", "Point"]] as const).map(([label, filter]) => [
              `downscaled ${s}px (${label})`,
              `${q(magick)} ${src} -auto-orient -filter ${filter} -resize ${s}x${s} -filter Lanczos -resize 200% -colorspace Gray d${s}${label}.png`,
            ] as [string, string]),
          ),
        ]
      : [["as shown", `cp ${q(input)} full.${EXT[type]}`]]
    const files = magick ? ["full.png", "boost.png", ...sizes.flatMap((s) => ["bicubic", "bilinear", "nearest"].map((l) => `d${s}${l}.png`))] : [`full.${EXT[type]}`]
    // one sandboxed script: decode + OCR every variant, write <file>.txt
    const script = [
      `cd ${q(dir)}`,
      "export MAGICK_MEMORY_LIMIT=512MiB MAGICK_DISK_LIMIT=1GiB MAGICK_TIME_LIMIT=20 OMP_THREAD_LIMIT=1",
      ...variants.map(([, c]) => `(${c} 2>/dev/null || true) &`),
      "wait",
      ...files.map((f) => `([ -f ${f} ] && ${q(tesseract)} ${f} ${f} --psm 11 -l eng >/dev/null 2>&1 || true) &`),
      "wait",
    ].join("\n")
    const timeout = opts.timeoutMs ?? 30_000
    let result
    if (opts.srt) {
      const settings = writeSrtSettings({ workspace: dir, allowedDomains: [], denyWrite: [] }, join(dir, ".srt"))
      result = await run(opts.srt, ["--settings", settings, "-c", script], timeout)
    } else result = await run("sh", ["-c", script], timeout)
    const passes = variants
      .map(([name], i) => ({ name, file: join(dir, `${files[i]}.txt`) }))
      .filter((p) => existsSync(p.file))
      .map((p) => ({ name: p.name, text: readFileSync(p.file, "utf8").replace(/\f/g, "").trim() }))
    return { status: passes.length ? "ok" : result.code === 0 ? "ok" : "failed", passes }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

const words = (t: string) => new Set(t.toLowerCase().match(/[a-z0-9@./:-]{4,}/g) ?? [])

/** Turns OCR passes into findings: injections, text only visible when downscaled, text only visible when boosted. */
export function analyseOcr(passes: readonly OcrPass[]): { findings: Finding[]; text: string } {
  const findings: Finding[] = []
  const shown = passes.find((p) => p.name === "as shown")?.text ?? ""
  const boosted = passes.find((p) => p.name === "contrast-boosted")?.text ?? ""
  const downs = passes.filter((p) => p.name.startsWith("downscaled"))
  const visible = words(shown)

  const hiddenWords = [...words(boosted)].filter((w) => !visible.has(w))
  if (hiddenWords.length >= 4)
    findings.push({ rule: "image/faint-text", severity: scanForInjection(boosted).length ? "high" : "medium", message: `Faint text that's hard for a person to see (${hiddenWords.slice(0, 6).join(" ")}…)` })

  for (const d of downs) {
    const fresh = [...words(d.text)].filter((w) => !visible.has(w) && !hiddenWords.includes(w))
    if (fresh.length >= 4) {
      const inj = scanForInjection(d.text).length > 0
      findings.push({
        rule: "image/scaling-text",
        severity: inj ? "critical" : "medium",
        message: `Text appears only after downscaling (${d.name}): ${fresh.slice(0, 6).join(" ")}… — an image-scaling attack shows the model different content than you see`,
      })
      break
    }
  }

  const all = passes.map((p) => p.text).join("\n")
  for (const f of scanForInjection(all)) findings.push({ rule: `image/text-${f.rule.replace("injection/", "")}`, severity: "high", message: `Text in the image looks like a prompt injection (${f.rule})` })

  // readable summary: lines that look like words (OCR on noisy images also returns junk), no repeats
  const looksLikeText = (l: string) => (l.match(/[A-Za-z]{3,}/g) ?? []).length >= 2
  const lines: string[] = []
  for (const l of all.split(/\n+/).map((x) => x.replace(/\s+/g, " ").trim()).filter(looksLikeText)) {
    const low = l.toLowerCase()
    if (lines.some((k) => k.toLowerCase().includes(low))) continue
    for (let i = lines.length - 1; i >= 0; i--) if (low.includes(lines[i]!.toLowerCase())) lines.splice(i, 1)
    lines.push(l)
  }
  return { findings, text: lines.join("\n").slice(0, 4000) }
}

export async function scanImage(bytes: Uint8Array, declaredMime?: string, opts: OcrOptions & { ocr?: boolean } = {}): Promise<ImageVerdict> {
  const inspection = inspectImage(bytes, declaredMime)
  const findings = [...inspection.findings]
  let ocr: OcrStatus = "skipped"
  let readableText = inspection.embeddedText.join("\n").slice(0, 2000)
  const decodable = !findings.some((f) => f.rule === "image/bomb" || f.rule === "image/unknown-format")
  if (opts.ocr !== false && decodable && inspection.type !== "svg") {
    const r = await ocrImage(bytes, inspection.type, opts)
    ocr = r.status
    if (r.passes.length) {
      const a = analyseOcr(r.passes)
      findings.push(...a.findings)
      readableText = [a.text, readableText].filter(Boolean).join("\n").slice(0, 4000)
    }
  }
  const verdict = findings.some((f) => f.severity !== "low" && f.severity !== "info") ? "suspicious" : "clean"
  return { ...inspection, findings: dedupe(findings), verdict, ocr, readableText }
}

function dedupe(fs: Finding[]): Finding[] {
  const seen = new Set<string>()
  return fs.filter((f) => (seen.has(f.rule) ? false : (seen.add(f.rule), true)))
}

export function describeOcrStatus(s: OcrStatus): string | undefined {
  if (s === "no-tesseract") return "text in images isn't checked (install tesseract to enable)"
  if (s === "no-sandbox") return "text in images isn't checked (needs the sandbox, srt)"
  if (s === "failed") return "text recognition failed for this image"
  return undefined
}
