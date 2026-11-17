# Contributing

- `bun install && bun test && bun run typecheck && bun run bench` must pass.
- New detection rules need a positive **and** a negative test (false positives erode trust as fast as misses do).
- `packages/core` must stay harness-agnostic: no imports from `@opencode/*`.
- The easiest first contribution is a new attack case in `bench/injection/cases.json`, or a scanner rule in `packages/core/src/scanner.ts`.
