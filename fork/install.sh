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
echo "✓ done. First run: komainu auth login   (Komainu keeps its own logins, separate from opencode)"
