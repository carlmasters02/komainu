# The Komainu harness (OpenCode + patches)

`komainu` is OpenCode with a small set of patches on top, the same model VSCodium uses for VS Code. There's no long-lived divergent fork to maintain: just patches re-applied to each upstream release.

```
fork/UPSTREAM      the OpenCode release we build on (e.g. v2.3.0)
fork/patches/      Komainu's changes, as git patches (small on purpose)
fork/build.sh      clone upstream@UPSTREAM → apply patches → build → fork/dist/komainu
fork/install.sh    install the binary to ~/.local/bin + global security config
fork/import-opencode-settings.ts   bring over MCP servers, plugins, agents… from an existing OpenCode setup
fork/design/       logo source (lion pixel art + wordmark)
```

## What the patches change
| Patch | Effect |
|---|---|
| 0001 identity | `komainu` command name; own config/data/service dirs (`~/.config/komainu`, `~/.local/share/komainu`) so it never clashes with a stock `opencode` |
| 0002 logo | guardian-lion home screen and KOMA·INU wordmark |
| 0003 hints | exit banner and "continue with `komainu -s …`" hints |

The security layers, Effort Advisor, spend tracker and `/advisor` `/spend` `/komainu` commands all live in the Komainu plugin (`packages/`), which `install.sh` enables globally, so they don't need patches at all.

## Build and install
```bash
fork/build.sh        # ~1 minute the first time, then seconds
fork/install.sh
komainu auth login   # first run only
komainu              # in any project
```

## Staying in sync with OpenCode
`.github/workflows/upstream-sync.yml` runs daily:
- **New OpenCode release, patches apply, build passes** → a PR bumping `fork/UPSTREAM`. Merge it, then `git pull && fork/build.sh && fork/install.sh`.
- **Patches conflict** → an issue. Fix them as below.

## Updating the patches
```bash
fork/build.sh vX.Y.Z                         # shows which patch failed
cd fork/.work/opencode-vX.Y.Z
git am --3way ../../patches/*.patch          # resolve conflicts, git add, git am --continue
git format-patch -q vX.Y.Z -o ../../patches  # rewrite the patch files
echo vX.Y.Z > ../../UPSTREAM
```

## Rules that keep sync cheap
- Put features in the **plugin** whenever the plugin API allows it; patch OpenCode only for things plugins can't do (branding, core behaviour).
- Keep each patch small and focused on one concern.
