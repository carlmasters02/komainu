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

if [ ! -f "$CFG/opencode.json" ] || [ "${1:-}" = "--force-config" ]; then
  echo "→ writing global config $CFG/opencode.json (Komainu plugin on for every project)"
  REPO="$REPO" CFG="$CFG" bun -e '
    const preset = await Bun.file(`${process.env.REPO}/presets/opencode.json`).json()
    preset.plugins[0].package = `${process.env.REPO}/packages/opencode-plugin`
    preset.update = "disable"   // updates come from the Komainu sync, never from upstream OpenCode
    await Bun.write(`${process.env.CFG}/opencode.json`, JSON.stringify(preset, null, 2) + "\n")
  '
else
  echo "→ keeping existing $CFG/opencode.json (use --force-config to replace it)"
fi
[ -f "$CFG/AGENTS.md" ] || cp "$REPO/presets/AGENTS.md" "$CFG/AGENTS.md"

case ":$PATH:" in
  *":$BIN:"*) ;;
  *) echo "! $BIN is not on your PATH. Add this to ~/.bashrc:  export PATH=\"$BIN:\$PATH\"" ;;
esac
echo "✓ done. First run: komainu auth login   (Komainu keeps its own logins, separate from opencode)"
