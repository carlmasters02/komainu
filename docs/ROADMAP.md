# Roadmap

## v0.1: this release
**Security**
- [x] Harness-agnostic core: shell risk analysis, secret redaction, sensitive paths, taint tracking, injection heuristics, write-time scanner, hash-chained audit log, srt sandbox wrapper
- [x] OpenCode v2 plugin wiring all of the above into tool/shell/permission hooks, with popups when something is blocked or an injection is detected
- [x] Hardened preset + read-only `security-reviewer` sub-agent
- [x] Security graph: audit log → pipeline view (`/komainu → Security graph`), local HTML, chain verification shown
- [x] Threat memory: flagged sources, denied domains and flagged images remembered across projects, scoped per publisher on shared hosts; recall only tightens (allow → ask)
- [x] Image guard: attached images checked in the sandbox (OCR as shown, contrast-boosted and downscaled; metadata; hidden files; decompression bombs) before the model sees them
- [x] Optional Neo4j: stream the graph to Neo4j and share threat memory across machines and teammates
- [x] Policy-level prompt-injection benchmark (15 cases)

**Harness**
- [x] Own identity: `komainu` command, guardian-lion home screen, separate settings; OpenCode + 3 small patches, re-applied to each upstream release by a daily workflow
- [x] Effort Advisor (Tier 0 rules, 0 tokens): suggests a better effort before a prompt runs, from each model's own effort ladder; `/advisor` suggest / auto / off
- [x] Spend tracker: today / 7 days / 30 days, tokens on subscription plans, daily budget warnings
- [x] Runtime switches via `/advisor`, `/spend`, `/komainu` (no restarts); one-step import of existing OpenCode settings

## v0.2: Close the known gaps
- [ ] Auto-wrap stdio MCP servers in srt (via `ctx.mcp.transform`)
- [ ] `komainu run`: launch the whole OpenCode process under srt, so built-in file tools are sandboxed too
- [ ] MCP pinning: hash tool descriptions on first use and alert when they change (rug-pull detection)
- [ ] Dependency gate: check new packages against OSV/deps.dev before install (age, downloads, typosquat distance, known vulns)
- [ ] `/security-review` command that runs the reviewer sub-agent on the current diff
- [ ] Explain blocks inside the permission prompt itself (today the reason arrives as a popup beside it)
- [ ] Image guard: more resampling filters and sizes per provider; optional local vision-model check for stylised text OCR misses
- [ ] Publish `@komainu/core` and `@komainu/opencode` to npm with provenance (sigstore)

## v0.3: Prove it
- [ ] Live benchmark: run real models (Claude, GPT, Gemini, Qwen and other local models) against injection cases end-to-end, stock vs Komainu
- [ ] Image-injection benchmark: faint-text and scaling-attack images (e.g. generated with Trail of Bits' Anamorpher) across providers
- [ ] Secure-code benchmark: vulnerable-code rate on standard secure-coding test suites with and without the scan-and-correct loop
- [ ] Public leaderboard page; community-submitted attack cases

## v1.0: Deeper harness
- [ ] Extend the fork where plugins can't reach: sandboxed built-in file tools, an always-on security panel (live taint status, blocked actions, scan findings)
- [ ] Team threat memory: signed, shared incident feeds (Neo4j or a plain file), with review before an entry applies to everyone
- [ ] Org policy files (managed, signed config); SARIF export; CI mode
- [ ] Adapters for other harnesses (Claude Code hooks, Codex, Goose, Cline)

## Next for the non-security features
Both stay **plugins, not patches**, to keep the OpenCode sync cheap.

### Effort Advisor
- **Tier 1 classifier, only when the rules are unsure:** a local model (e.g. `qwen3:4b` via Ollama, $0) or the cheapest cloud model; ~200 tokens in, one word out (`low`/`medium`/`high`); cached by prompt fingerprint.
- **Learning (0 tokens):** log outcomes locally (re-prompts, retries, failed tools) to tune thresholds per user.
- **Model suggestions:** recommend a cheaper model, not just a lower effort, using a profile table (effort levels, relative cost, strengths).
- **Tokens-saved counter** in the footer.

### Spend tracker
- Per-provider and per-model breakdown in the sidebar.
- Monthly budget alongside the daily one, with an optional hard stop.
- Subscription plans (Claude Pro/Max, ChatGPT/Codex, Copilot): remaining quota per window where the provider reports it, plus an "API-equivalent value".
