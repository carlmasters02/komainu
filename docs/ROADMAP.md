# Roadmap

## v0.1: OpenCode plugin (this release)
- [x] Harness-agnostic core: shell risk analysis, secret redaction, sensitive paths, taint tracking, injection heuristics, write-time scanner, hash-chained audit log, srt sandbox wrapper
- [x] OpenCode v2 plugin wiring all of the above into tool/shell/permission hooks
- [x] Hardened preset + read-only `security-reviewer` sub-agent
- [x] Policy-level prompt-injection benchmark (15 cases)

### Shipped after v0.1
- **Security graph**: audit log → pipeline view (`/komainu → Security graph`), local HTML, chain verification shown.
- **Threat memory**: flagged sources and denied domains are remembered across projects; recall only tightens (allow → ask).
- **Image guard**: attached images are checked in the sandbox (OCR at full size, contrast-boosted and downscaled; metadata; hidden files) before the model sees them.
- **Neo4j (optional)**: stream the graph to Neo4j and share threat memory across machines/teammates.

## v0.2: Close the known gaps
- [ ] Auto-wrap stdio MCP servers in srt (via `ctx.mcp.transform`)
- [ ] `komainu run`: launch the whole OpenCode process under srt, so built-in file tools are sandboxed too
- [ ] MCP pinning: hash tool descriptions on first use and alert when they change (rug-pull detection)
- [ ] Dependency gate: check new packages against OSV/deps.dev before install (age, downloads, typosquat distance, known vulns)
- [ ] `/security-review` command that runs the reviewer sub-agent on the current diff
- [ ] Publish `@komainu/core` and `@komainu/opencode` to npm with provenance (sigstore)

## v0.3: Prove it
- [ ] Live benchmark: run real models (Claude, GPT, Gemini, Qwen and other local models) against injection cases end-to-end, stock vs Komainu
- [ ] Secure-code benchmark: vulnerable-code rate on standard secure-coding test suites with and without the scan-and-correct loop
- [ ] Public leaderboard page; community-submitted attack cases

## v1.0: Own harness
- [ ] Decide: maintain a thin OpenCode fork (sandboxed file tools, security UI panel) or write a standalone harness on `@komainu/core`
- [ ] Security panel in the TUI: live taint status, blocked actions, scan findings
- [ ] Org policy files (managed, signed config); SARIF export; CI mode
- [ ] Adapters for other harnesses (Claude Code hooks, Codex, Goose, Cline)

## Future ideas (not security-related; design notes only, nothing implemented)

Both should be built as **plugins, not patches**, to keep the OpenCode sync cheap.

### Effort Advisor: right-size effort to save tokens
**Shipped (v0.2):** Tier 0 rules; asks after you send a prompt and before it runs (silent when effort fits); `suggest`/`auto`/`off` via `/advisor`; 5 difficulty levels mapped onto each model's own effort ladder; audit entries. **Next:** Tier 1 local-model classifier, learning from outcomes, one-key apply, tokens-saved counter.
Goal: before a prompt runs, suggest a better effort level (or model) when the current one is clearly too high or too low. Its own cost must be near zero.
- **Tier 0: free local rules (0 tokens)** for clear-cut cases: prompt length, files/code blocks mentioned, task keywords ("rename", "fix typo" → low; "architect", "debug why", "refactor across" → high), repo signals (diff size, files likely involved).
- **Tier 1: tiny classifier, only when Tier 0 is unsure.** Prefer a local model (e.g. `qwen3:4b` via Ollama, $0), else the cheapest cloud model. Input: truncated prompt + model name (~200 tokens). Output: one word (`low`/`medium`/`high`). Cache by prompt fingerprint.
- **Model profile table:** supported effort levels, relative cost per level, strengths. Recommend the lowest effort likely to succeed; optionally suggest a cheaper model.
- **Learning (0 tokens):** log outcomes locally (re-prompts, retries, failed tools) to tune thresholds per user.
- **UX:** hint under the prompt box ("high → medium is likely enough, ~40% cheaper"), applied with one keypress, never silently. Show a running "estimated tokens saved" counter.
- Open question: which plugin hook sees the prompt before it is sent (prompt-footer slot exists for the hint).

### Universal spend tracker
**Shipped (v0.2):** today/7d/30d panel + home line from OpenCode's stats API, token view for subscriptions, daily budget toasts. **Next:** per-provider breakdown, monthly budget, subscription quota windows.
- **Check for redundancy first:** OpenCode already shows per-session cost (sidebar) and has `opencode stats`. Confirm what newer versions add before building.
- **Likely gaps:** cumulative totals across sessions/days by provider and model; budgets with alerts (warn at 80%, optional hard stop); subscription plans (Claude Pro/Max, ChatGPT/Codex, Copilot) show $0, so track tokens/requests, an "API-equivalent value", and remaining quota where the provider reports it.
- **Architecture:** plugin records token usage per model call into a local ledger in Komainu's data folder (nothing leaves the machine); prices from OpenCode's built-in model price data; sidebar panel (`sidebar.content` slot) with today/week/month, per-provider breakdown and a budget bar.
