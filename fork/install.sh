#!/usr/bin/env bash
# Installs the built `komainu` command and Komainu's global security setup.
#   fork/install.sh                  # install binary; create config only if missing
#   fork/install.sh --force-config   # also overwrite ~/.config/komainu config with the preset
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${KOMAINU_BIN_DIR:-$HOME/.local/bin}"
CFG="${XDG_CONFIG_HOME:-$HOME/.config}/komainu"

[ -x "$REPO/fork/dist/komainu" ] || { echo "✗ run fork/build.sh first" >&2; exit 1; }

echo "→ installing plugin dependencies"
(cd "$REPO" && bun install >/dev/null)

echo "→ installing komainu → $BIN/komainu"
mkdir -p "$BIN" "$CFG"
install -m 755 "$REPO/fork/dist/komainu" "$BIN/komainu"
# komainu-update sits next to the binary: komainu's /update and its update notice run it.
printf '%s\n' '#!/usr/bin/env bash' \
  '# Installed by Komainu (fork/install.sh). Updates Komainu code and binary; /update inside komainu runs this.' \
  "export KOMAINU_BIN_DIR=\"$BIN\"" \
  "exec \"$REPO/fork/update.sh\" \"\$@\"" > "$BIN/komainu-update"
chmod 755 "$BIN/komainu-update"

# The sandbox tool (srt). It's published for Node 22.12+, but runs the same on Bun (Komainu's sandbox tests pass
# either way). If it's missing or can't run (no Node, or an old one), install it with Bun and run it on Bun, so
# Node.js isn't a requirement.
if ! { command -v srt >/dev/null && srt -c true >/dev/null 2>&1; }; then
  echo "→ setting up the sandbox tool (srt)"
  bun add -g @anthropic-ai/sandbox-runtime >/dev/null 2>&1 || true
  SRT_CLI="${BUN_INSTALL:-$HOME/.bun}/install/global/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js"
  if [ -f "$SRT_CLI" ]; then
    printf '#!/bin/sh\n# Installed by Komainu (fork/install.sh): runs the sandbox tool on Bun, so Node.js is not needed.\nexec "%s" --bun "%s" "$@"\n' "$(command -v bun)" "$SRT_CLI" > "$BIN/srt"
    chmod 755 "$BIN/srt"
  fi
  if PATH="$BIN:$PATH" srt -c true >/dev/null 2>&1; then
    echo "  ✓ sandbox ready"
    FOUND="$(command -v srt || true)"
    if [ -n "$FOUND" ] && [ "$FOUND" != "$BIN/srt" ]; then
      echo "! an older srt at $FOUND comes first on your PATH and doesn't work; remove it: npm rm -g @anthropic-ai/sandbox-runtime"
    fi
  else
    echo "! the sandbox isn't working yet. On Linux, install bubblewrap, socat and ripgrep (see the README), then run fork/install.sh again."
  fi
fi

if [ ! -f "$CFG/opencode.json" ] || [ "${1:-}" = "--force-config" ]; then
  echo "→ writing global config $CFG/opencode.json (Komainu plugin on for every project)"
  REPO="$REPO" CFG="$CFG" bun -e '
    const preset = await Bun.file(`${process.env.REPO}/presets/opencode.json`).json()
    preset.plugins[0].package = `${process.env.REPO}/packages/opencode-plugin`
    await Bun.write(`${process.env.CFG}/opencode.json`, JSON.stringify(preset, null, 2) + "\n")
  '
else
  echo "→ keeping existing $CFG/opencode.json (use --force-config to replace it)"
  # Older installs turned update checks off; they now come from Komainu's own releases, so turn them on once.
  if [ ! -f "$CFG/.update-checks-on" ]; then
    CFG="$CFG" bun -e '
      const file = `${process.env.CFG}/opencode.json`
      try {
        const config = await Bun.file(file).json()
        if (config.update === "disable") {
          config.update = "notify"
          await Bun.write(file, JSON.stringify(config, null, 2) + "\n")
        }
      } catch {}
    ' && touch "$CFG/.update-checks-on"
  fi
fi
[ -f "$CFG/AGENTS.md" ] || cp "$REPO/presets/AGENTS.md" "$CFG/AGENTS.md"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *)
    case "${SHELL:-}" in
      */zsh) RC="~/.zshrc" ;;
      */fish) RC="~/.config/fish/config.fish" ;;
      *) RC="~/.bashrc" ;;
    esac
    if [ "$RC" = "~/.config/fish/config.fish" ]; then LINE="fish_add_path $BIN"; else LINE="export PATH=\"$BIN:\$PATH\""; fi
    echo "! $BIN is not on your PATH. Run this now, and add it to $RC:"
    echo "    $LINE"
    ;;
esac
echo "✓ done. Start it in any project folder with: komainu   (type /models and pick a Free model, or run komainu auth login to use your own account)"
