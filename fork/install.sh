#!/usr/bin/env bash
# Installs the built `komainu` command and Komainu's global security setup.
#   fork/install.sh                  # install binary; create config only if missing
#   fork/install.sh --force-config   # also overwrite ~/.config/komainu config with the preset
set -euo pipefail

export PATH="${BUN_INSTALL:-$HOME/.bun}/bin:$PATH"   # finds Bun even before the terminal is reopened
command -v bun >/dev/null || { echo "✗ Bun isn't installed. Install it with: curl -fsSL https://bun.sh/install | bash   then run this again." >&2; exit 1; }

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
  # Installed into Komainu's own folder (not Bun's global one, whose `srt` link needs Node.js).
  SRT_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/komainu/sandbox-runtime"
  mkdir -p "$SRT_DIR"
  [ -f "$SRT_DIR/package.json" ] || echo '{ "private": true }' > "$SRT_DIR/package.json"
  (cd "$SRT_DIR" && bun add @anthropic-ai/sandbox-runtime >/dev/null 2>&1) || true
  SRT_CLI="$SRT_DIR/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js"
  if [ -f "$SRT_CLI" ]; then
    printf '#!/bin/sh\n# Installed by Komainu (fork/install.sh): runs the sandbox tool on Bun, so Node.js is not needed.\nexec "%s" --bun "%s" "$@"\n' "$(command -v bun)" "$SRT_CLI" > "$BIN/srt"
    chmod 755 "$BIN/srt"
    # Earlier Komainu versions used `bun add -g`, which left a Node-only `srt` link in Bun's folder. Remove it
    # only when it is that link and it doesn't run.
    OLD="${BUN_INSTALL:-$HOME/.bun}/bin/srt"
    case "$(readlink "$OLD" 2>/dev/null || true)" in
      *install/global/node_modules/@anthropic-ai/sandbox-runtime/*) STALE=1 ;;
      *) STALE= ;;
    esac
    if [ -n "$STALE" ] && ! "$OLD" -c true >/dev/null 2>&1; then
      bun remove -g @anthropic-ai/sandbox-runtime >/dev/null 2>&1 || true
      rm -f "$OLD"; hash -r
    fi
  fi
  if PATH="$BIN:$PATH" srt -c true >/dev/null 2>&1; then
    echo "  ✓ sandbox ready"
    FOUND="$(command -v srt || true)"
    if [ -n "$FOUND" ] && [ "$FOUND" != "$BIN/srt" ]; then
      echo "! another srt at $FOUND comes first on your PATH and doesn't work. Remove it (if it came from npm: npm rm -g @anthropic-ai/sandbox-runtime) so the one in $BIN is used."
    fi
  else
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = "1" ]; then
      echo "! the sandbox can't start: Ubuntu 24.04+ restricts user namespaces, which it needs. To allow them, run:"
      echo "    echo 'kernel.apparmor_restrict_unprivileged_userns=0' | sudo tee /etc/sysctl.d/60-komainu-userns.conf && sudo sysctl --system"
      echo "  (this turns off an Ubuntu hardening setting for all programs), then run fork/install.sh again."
    else
      echo "! the sandbox isn't working yet. On Linux, install bubblewrap, socat and ripgrep (see the README), then run fork/install.sh again."
    fi
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
      */zsh) RC="$HOME/.zshrc" ;;
      */fish) RC="$HOME/.config/fish/config.fish" ;;
      *) RC="$HOME/.bashrc" ;;
    esac
    if [ "$RC" = "$HOME/.config/fish/config.fish" ]; then LINE="fish_add_path $BIN"; else LINE="export PATH=\"$BIN:\$PATH\""; fi
    if ! grep -qsF "$LINE" "$RC"; then
      mkdir -p "$(dirname "$RC")"
      printf '\n# added by Komainu: where the komainu command lives\n%s\n' "$LINE" >> "$RC"
    fi
    echo "✓ added $BIN to your PATH in ${RC/#"$HOME"/"~"}. Open a new terminal before running komainu."
    ;;
esac
echo "✓ done. Start it in any project folder with: komainu   (type /models and pick a Free model, or run komainu auth login to use your own account)"
