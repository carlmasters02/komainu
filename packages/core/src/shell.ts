/**
 * Static risk analysis for shell commands proposed by an agent.
 *
 * This is a *speed bump and signal*, not a security boundary: shell is Turing-complete and a
 * determined attacker can always obfuscate. The boundary is the OS sandbox (see sandbox.ts).
 * The analyzer's job is to (a) stop obvious catastrophes before they reach the sandbox,
 * (b) surface intent to the user in plain words, and (c) feed the taint-aware policy.
 */
import { isSensitivePath } from "./secrets.js"
import type { Finding, Severity } from "./types.js"

export interface Segment {
  readonly raw: string
  readonly argv: readonly string[]
}

/** Split on control operators and pull out $(...) / `...` substitutions, respecting quotes. */
export function splitCommand(command: string): Segment[] {
  const pieces: string[] = []
  const subs: string[] = []
  let cur = ""
  let quote: '"' | "'" | null = null
  for (let i = 0; i < command.length; i++) {
    const c = command[i]!
    const next = command[i + 1]
    if (quote) {
      if (c === quote) quote = null
      else if (c === "\\" && quote === '"' && next !== undefined) {
        cur += c + next
        i++
        continue
      }
      // command substitution is live inside double quotes
      if (quote === '"' && c === "$" && next === "(") {
        const end = matchParen(command, i + 1)
        subs.push(command.slice(i + 2, end))
      }
      cur += c
      continue
    }
    if (c === "'" || c === '"') {
      quote = c
      cur += c
      continue
    }
    if (c === "\\" && next !== undefined) {
      cur += c + next
      i++
      continue
    }
    if (c === "$" && next === "(") {
      const end = matchParen(command, i + 1)
      subs.push(command.slice(i + 2, end))
      cur += command.slice(i, end + 1)
      i = end
      continue
    }
    if (c === "`") {
      const end = command.indexOf("`", i + 1)
      const stop = end === -1 ? command.length : end
      subs.push(command.slice(i + 1, stop))
      cur += command.slice(i, stop + 1)
      i = stop
      continue
    }
    if (c === ";" || c === "\n" || c === "|" || (c === "&" && next === "&") || c === "(" || c === ")" || c === "{" || c === "}") {
      pieces.push(cur)
      cur = ""
      if ((c === "|" || c === "&") && next === c) i++
      continue
    }
    if (c === "&") {
      pieces.push(cur)
      cur = ""
      continue
    }
    cur += c
  }
  pieces.push(cur)
  const all = [...pieces, ...subs.flatMap((s) => splitCommand(s).map((x) => x.raw))]
  return all.map((raw) => raw.trim()).filter(Boolean).map((raw) => ({ raw, argv: tokenize(raw) }))
}

function matchParen(s: string, open: number): number {
  let depth = 0
  for (let i = open; i < s.length; i++) {
    if (s[i] === "(") depth++
    else if (s[i] === ")" && --depth === 0) return i
  }
  return s.length - 1
}

export function tokenize(segment: string): string[] {
  const out: string[] = []
  let cur = ""
  let quote: string | null = null
  let has = false
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i]!
    if (quote) {
      if (c === quote) quote = null
      else if (c === "\\" && quote === '"' && i + 1 < segment.length) cur += segment[++i]
      else cur += c
      continue
    }
    if (c === "'" || c === '"') {
      quote = c
      has = true
      continue
    }
    if (c === "\\" && i + 1 < segment.length) {
      cur += segment[++i]
      has = true
      continue
    }
    if (/\s/.test(c)) {
      if (has || cur) out.push(cur)
      cur = ""
      has = false
      continue
    }
    cur += c
  }
  if (has || cur) out.push(cur)
  return out
}

/** Strip env assignments and transparent wrappers so `FOO=1 sudo nice rm` analyses `rm` (and records sudo). */
function program(argv: readonly string[]): { name: string; args: string[]; wrappers: string[] } {
  const wrappers: string[] = []
  let i = 0
  while (i < argv.length) {
    const t = argv[i]!
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
      i++
      continue
    }
    const base = t.split("/").pop()!
    if (["sudo", "doas", "nice", "nohup", "time", "env", "command", "exec", "xargs", "timeout", "stdbuf"].includes(base)) {
      wrappers.push(base)
      i++
      // skip wrapper flags (best effort)
      while (i < argv.length && argv[i]!.startsWith("-")) i++
      if (base === "timeout" && i < argv.length && /^\d/.test(argv[i]!)) i++
      continue
    }
    return { name: base, args: argv.slice(i + 1) as string[], wrappers }
  }
  // a wrapper with nothing after it is the program itself (bare `env` dumps the environment)
  const last = wrappers.at(-1)
  if (last) return { name: last, args: [], wrappers: wrappers.slice(0, -1) }
  return { name: "", args: [], wrappers }
}

const NETWORK_TOOLS = new Set(["curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "sftp", "rsync", "ftp", "telnet", "http", "https", "xh", "aria2c"])
const INTERPRETERS = new Set(["sh", "bash", "zsh", "dash", "ksh", "fish", "python", "python3", "node", "bun", "deno", "perl", "ruby", "php", "pwsh", "powershell"])
const READERS = new Set(["cat", "less", "more", "head", "tail", "bat", "xxd", "od", "strings", "base64", "grep", "rg", "awk", "sed", "cp", "tar", "zip", "gzip", "openssl"])

const f = (rule: string, severity: Severity, message: string): Finding => ({ rule, severity, message })

const isRootish = (p: string) => /^(?:\/|\/\*|~|~\/|~\/\*|\$HOME\/?|\$\{HOME\}\/?|\*|\.\.|\.\.\/|\/(?:etc|usr|bin|boot|var|lib|opt|home|Users|System)\/?)$/.test(p)

export function analyzeShell(command: string): Finding[] {
  const findings: Finding[] = []
  const segments = splitCommand(command)
  const programs = segments.map((s) => program(s.argv))
  const names = programs.map((p) => p.name)
  const hasNetwork = names.some((n) => NETWORK_TOOLS.has(n)) || /\/dev\/tcp\//.test(command)
  let readsSensitive = false

  // whole-command patterns
  if (/:\(\)\s*\{\s*:\|:&\s*\};:/.test(command.replace(/\s+/g, ""))) findings.push(f("fork-bomb", "critical", "Fork bomb"))
  if (/\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\|\s*(?:python3?|node|perl|ruby)\b/.test(command) && hasNetwork)
    findings.push(f("pipe-to-shell", "critical", "Downloads remote content and executes it (curl | sh)"))
  if (/base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba|z)?sh/.test(command) || /\beval\s+["'$`(]*\$\(.*base64/.test(command))
    findings.push(f("obfuscated-exec", "critical", "Decodes and executes obfuscated content"))
  if (/>\s*\/dev\/(?:sd|nvme|disk|hd)/.test(command)) findings.push(f("raw-disk-write", "critical", "Writes directly to a block device"))
  if (/\/dev\/tcp\//.test(command)) findings.push(f("dev-tcp", "high", "Opens a raw TCP socket via /dev/tcp (common reverse-shell idiom)"))
  if (/>>?\s*~?\/?[^\s]*\/?\.(?:bashrc|zshrc|profile|bash_profile|zprofile)\b/.test(command))
    findings.push(f("shell-rc-write", "high", "Modifies a shell startup file (persistence)"))
  if (/\bLD_PRELOAD=|\bDYLD_INSERT_LIBRARIES=/.test(command)) findings.push(f("preload-injection", "high", "Injects a shared library into processes"))

  for (const [i, { name, args, wrappers }] of programs.entries()) {
    const seg = segments[i]!.raw
    const flags = args.filter((a) => a.startsWith("-")).join(" ")
    const targets = args.filter((a) => !a.startsWith("-"))

    if (wrappers.includes("sudo") || wrappers.includes("doas") || name === "su")
      findings.push(f("privilege-escalation", "high", `Runs with elevated privileges: ${seg}`))

    if (args.some((a) => !a.startsWith("-") && isSensitivePath(a)) && (READERS.has(name) || NETWORK_TOOLS.has(name) || INTERPRETERS.has(name))) {
      readsSensitive = true
      findings.push(f("sensitive-read", "high", `Accesses a credential/secret file: ${seg}`))
    }
    if (/@\S*(?:\.env|id_rsa|\.pem|credentials)/.test(seg)) readsSensitive = true

    switch (name) {
      case "rm": {
        const recursive = /(?:^|\s)-[a-zA-Z]*[rR]|--recursive/.test(flags)
        if (recursive && targets.some(isRootish)) findings.push(f("rm-root", "critical", `Recursive delete of a root/home path: ${seg}`))
        else if (recursive && /f/.test(flags)) findings.push(f("rm-rf", "medium", `Forced recursive delete: ${seg}`))
        if (/--no-preserve-root/.test(flags)) findings.push(f("rm-root", "critical", "rm --no-preserve-root"))
        break
      }
      case "mkfs":
      case "fdisk":
      case "parted":
      case "wipefs":
        findings.push(f("disk-format", "critical", `Disk partitioning/formatting: ${seg}`))
        break
      case "dd":
        if (args.some((a) => /^of=\/dev\//.test(a))) findings.push(f("raw-disk-write", "critical", `dd to a device: ${seg}`))
        break
      case "chmod":
        if (/(?:^|\s)(?:-R\s+)?0?777\b/.test(args.join(" ")) && targets.some(isRootish)) findings.push(f("chmod-root", "critical", seg))
        else if (/\b0?777\b|a\+rwx|o\+w/.test(args.join(" "))) findings.push(f("chmod-world-writable", "medium", `Makes files world-writable: ${seg}`))
        if (/\+s\b|u\+s|g\+s|\b[24][0-7]{3}\b/.test(args.join(" "))) findings.push(f("setuid", "high", `Sets setuid/setgid bit: ${seg}`))
        break
      case "chown":
        if (targets.some(isRootish)) findings.push(f("chown-root", "high", seg))
        break
      case "git": {
        const sub = targets[0]
        if (sub === "push" && /(?:^|\s)(?:-f|--force(?!-with-lease))/.test(flags)) findings.push(f("git-force-push", "high", "Force-push rewrites remote history"))
        else if (sub === "push") findings.push(f("git-push", "medium", "Publishes commits to a remote"))
        if (sub === "reset" && /--hard/.test(flags)) findings.push(f("git-reset-hard", "medium", "Discards uncommitted work"))
        if (sub === "clean" && /-[a-zA-Z]*f/.test(flags)) findings.push(f("git-clean", "medium", "Deletes untracked files"))
        if (sub === "config" && /credential|core\.hooksPath|core\.sshCommand|url\..*insteadOf/.test(args.join(" ")))
          findings.push(f("git-config-hijack", "high", `Changes git credential/hook/transport config: ${seg}`))
        if (sub === "remote" && targets[1] === "add") findings.push(f("git-remote-add", "medium", seg))
        break
      }
      case "npm":
      case "pnpm":
      case "yarn":
      case "bun":
      case "pip":
      case "pip3":
      case "uv":
      case "cargo":
      case "gem":
      case "go": {
        const sub = targets[0]
        if (sub === "publish") findings.push(f("package-publish", "high", `Publishes a package: ${seg}`))
        if (["install", "i", "add"].includes(sub ?? "") && targets.length > 1)
          findings.push(f("package-install", "low", `Installs new dependency: ${targets.slice(1).join(" ")}`))
        if (/--index-url|--extra-index-url|--registry/.test(flags)) findings.push(f("custom-registry", "medium", `Uses a non-default package registry: ${seg}`))
        break
      }
      case "crontab":
      case "launchctl":
      case "systemctl":
        findings.push(f("persistence", "high", `Modifies scheduled/background services: ${seg}`))
        break
      case "history":
        if (/-c|-d/.test(flags)) findings.push(f("anti-forensics", "high", "Clears shell history"))
        break
      case "env":
      case "printenv":
      case "set":
      case "export":
        if (targets.length === 0 || name === "printenv") findings.push(f("env-dump", "medium", "Dumps environment variables (may contain secrets)"))
        break
      case "eval":
        findings.push(f("eval", "medium", `eval of dynamic content: ${seg}`))
        break
      case "kill":
      case "pkill":
      case "killall":
        if (/-9\s+-1|\s-1\b/.test(seg)) findings.push(f("kill-all", "critical", "Kills every process"))
        break
      case "shutdown":
      case "reboot":
      case "halt":
      case "poweroff":
        findings.push(f("power", "high", seg))
        break
    }

    if (NETWORK_TOOLS.has(name)) {
      findings.push(f("network-egress", "low", `Network access: ${seg}`))
      if (/(?:^|\s)(?:-d|--data(?:-binary|-raw|-urlencode)?|-F|--form|-T|--upload-file|--post-file)\b/.test(seg))
        findings.push(f("network-upload", "medium", `Uploads data to a remote host: ${seg}`))
      if (name === "nc" || name === "ncat" || name === "netcat" || name === "socat")
        if (/-e\s|-c\s|exec:/.test(seg)) findings.push(f("reverse-shell", "critical", `Binds a shell to a socket: ${seg}`))
    }
    if (INTERPRETERS.has(name) && /(?:^|\s)-c\b|(?:^|\s)-e\b/.test(flags)) {
      // recurse into inline code for shells; for others flag only network+exec idioms
      const code = args[args.findIndex((a) => a === "-c" || a === "-e") + 1]
      if (code && ["sh", "bash", "zsh", "dash"].includes(name)) findings.push(...analyzeShell(code))
      else if (code && /socket|subprocess|child_process|os\.system|urllib|requests\.|fetch\(|http\.request/.test(code))
        findings.push(f("inline-code-net-exec", "medium", `Inline ${name} code touching network/processes`))
    }
  }

  if (readsSensitive && hasNetwork)
    findings.push(f("secret-exfiltration", "critical", "Reads credential files and sends data over the network in one command"))

  return dedupe(findings)
}

function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>()
  return findings.filter((x) => {
    const k = `${x.rule}|${x.message}`
    if (seen.has(k)) return false
    seen.add(k)
    return true
  })
}
