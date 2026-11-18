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
`.github/workflows/upstream-sync.yml` runs every 6 hours:
- **New OpenCode release, patches apply, build and tests pass** → it bumps `fork/UPSTREAM` on main and publishes a release `vX.Y.Z-komainu` with binaries for linux-x64, linux-arm64, darwin-arm64 and darwin-x64 as `.tar.xz` (what `komainu-update` downloads, about a third of the size), `.tar.gz` (fallback when `xz` is missing) and the plain binary (for older update scripts), plus `SHA256SUMS`.
- **Patches conflict or tests fail** → an issue. Fix the patches as below and push; the push publishes the release.

Users get it like any OpenCode update: patch `0004` makes OpenCode's updater check Komainu's latest GitHub release (the startup notice and `/update`), and install it by running `komainu-update`, which `fork/install.sh` puts next to the binary. `komainu-update` (`fork/update.sh`) pulls the repo, re-runs itself from the freshly pulled copy, downloads and checksum-verifies the archive for the machine (downloads give up after 30 s without progress and retry; it builds from source if there is no binary or the download fails), and reinstalls. It reports progress in the terminal, and writes it to `~/.local/state/komainu/update-progress.json`, which komainu shows as toasts while `/update` runs.

Komainu-only fixes to the binary (a patch change with no new OpenCode release): put a number in `fork/REVISION` (`1`, `2`, …) and push; that publishes `vX.Y.Z-komainu.N`. The next OpenCode sync removes the file. Plugin-only changes need no release: `komainu-update` always pulls the latest code.

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
