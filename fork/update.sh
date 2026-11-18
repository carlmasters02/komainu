#!/usr/bin/env bash
# Updates Komainu to the newest release: the latest code from GitHub plus the matching `komainu` binary.
# Every OpenCode release gets a matching Komainu release automatically (.github/workflows/upstream-sync.yml),
# so this keeps you in step with OpenCode's fixes and security updates.
#   komainu-update                  # update to the newest release (what /update inside komainu runs)
#   komainu-update 2.3.2-komainu    # update to a specific release
#   fork/update.sh --source         # skip the prebuilt download and build from source
# Env: KOMAINU_BIN_DIR (where komainu is installed, default ~/.local/bin),
#      KOMAINU_RELEASE_BASE (download base URL, for testing)
set -euo pipefail

FORK="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$FORK")"
OWNER_REPO="carlmasters02/komainu"
STATE="${XDG_STATE_HOME:-$HOME/.local/state}/komainu"
PROGRESS="$STATE/update-progress.json"
FROM_SOURCE=false
WANT=""
for arg in "$@"; do
  case "$arg" in
    --source) FROM_SOURCE=true ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) WANT="${arg#v}" ;;
  esac
done

# Progress: a live line in a terminal, and a small JSON file that komainu shows while /update runs.
TTY=false; [ -t 1 ] && TTY=true
progress() { # stage message
  local msg="${2//\"/\'}"
  printf '{"stage":"%s","message":"%s","at":%s}\n' "$1" "$msg" "$(date +%s)" > "$PROGRESS.tmp" && mv "$PROGRESS.tmp" "$PROGRESS"
  if $TTY; then printf '\r\033[K→ %s' "$2"; [ "$1" = live ] || printf '\n'
  elif [ "$1" != live ]; then echo "→ $2"; fi
}

# One update at a time (several komainu windows may offer it at once).
mkdir -p "$STATE"
LOCK="$STATE/update.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  if [ -n "$(find "$LOCK" -maxdepth 0 -mmin +30 2>/dev/null)" ]; then rm -rf "$LOCK"; mkdir "$LOCK"
  else echo "✗ another Komainu update is running (remove $LOCK if it is stuck)" >&2; exit 1; fi
fi
TMP="$(mktemp -d)"
cleanup() { rm -rf "$LOCK" "$TMP"; }
trap 'cleanup' EXIT
trap 'progress failed "Update failed. Run komainu-update in a terminal to see why."' ERR

# Downloads fail fast on a dead connection (under 2 KB/s for 30 s) and retry, instead of hanging forever.
CURL=(curl -fsSL --connect-timeout 15 --retry 3 --retry-delay 2 --speed-limit 2048 --speed-time 30)

if [ -z "$WANT" ]; then
  WANT="$("${CURL[@]}" -H 'accept: application/vnd.github+json' \
    "https://api.github.com/repos/$OWNER_REPO/releases/latest" 2>/dev/null \
    | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1 || true)"
fi

if [ -d "$REPO/.git" ] && [ -z "${KOMAINU_UPDATE_PULLED:-}" ]; then
  progress pull "Getting the latest Komainu code"
  if ! git -C "$REPO" pull --ff-only --quiet; then
    progress failed "Could not update $REPO (local changes?). Commit or stash them, then retry."
    exit 1
  fi
  # Carry on with the script we just pulled, so this update already uses its newest logic.
  cleanup; trap - EXIT ERR
  args=(); $FROM_SOURCE && args+=(--source); [ -n "$WANT" ] && args+=("$WANT")
  KOMAINU_UPDATE_PULLED=1 exec "$FORK/update.sh" ${args[@]+"${args[@]}"}
fi
[ -n "$WANT" ] || WANT="$(sed 's/^v//' "$FORK/UPSTREAM")-komainu$([ -s "$FORK/REVISION" ] && echo ".$(cat "$FORK/REVISION")")"

progress deps "Installing plugin dependencies"
(cd "$REPO" && bun install >/dev/null)

case "$(uname -s)" in Linux) OS=linux ;; Darwin) OS=darwin ;; *) OS="" ;; esac
case "$(uname -m)" in x86_64|amd64) ARCH=x64 ;; aarch64|arm64) ARCH=arm64 ;; *) ARCH="" ;; esac

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }
size() { stat -c %s "$1" 2>/dev/null || stat -f %z "$1" 2>/dev/null || echo 0; }

# Fetches a file in the background and reports how far along it is.
fetch() { # url dest
  local total now pid
  total="$("${CURL[@]}" -I "$1" 2>/dev/null | tr -d '\r' | awk 'tolower($1)=="content-length:"{n=$2} END{print n+0}')"
  "${CURL[@]}" -o "$2" "$1" & pid=$!
  while kill -0 "$pid" 2>/dev/null; do
    now=$(size "$2")
    if [ "${total:-0}" -gt 0 ]; then progress live "Downloading Komainu $WANT: $((now * 100 / total))% ($((now / 1048576)) of $((total / 1048576)) MB)"
    else progress live "Downloading Komainu $WANT: $((now / 1048576)) MB"; fi
    sleep 1
  done
  $TTY && printf '\n'
  wait "$pid"
}

download() {
  [ -n "$OS" ] && [ -n "$ARCH" ] || return 1
  local base="${KOMAINU_RELEASE_BASE:-https://github.com/$OWNER_REPO/releases/download}/v$WANT"
  local name="komainu-$OS-$ARCH" ext=tar.gz unpack=-xzf asset expected
  # xz is about a third of the plain binary; macOS tar reads it natively, Linux needs the xz tool.
  if [ "$OS" = darwin ] || command -v xz >/dev/null; then ext=tar.xz; unpack=-xJf; fi
  "${CURL[@]}" -o "$TMP/SHA256SUMS" "$base/SHA256SUMS" || return 1
  asset="$name.$ext"
  if ! grep -q " \*\{0,1\}$asset\$" "$TMP/SHA256SUMS"; then asset="$name"; unpack=""; fi # older releases: plain binary
  fetch "$base/$asset" "$TMP/$asset" || return 1
  progress verify "Checking the download"
  expected="$(awk -v a="$asset" '$2 == a || $2 == "*"a {print $1}' "$TMP/SHA256SUMS")"
  if [ -z "$expected" ] || [ "$(sha256 "$TMP/$asset")" != "$expected" ]; then
    echo "✗ checksum mismatch for $asset; not installing it" >&2; return 1
  fi
  if [ -n "$unpack" ]; then tar "$unpack" "$TMP/$asset" -C "$TMP" && mv "$TMP/komainu" "$TMP/$name"; fi
  chmod 755 "$TMP/$name"
  # Apple Silicon refuses unsigned binaries; an ad-hoc signature is enough for a binary you downloaded yourself.
  if [ "$OS" = darwin ] && command -v codesign >/dev/null; then codesign --force --sign - "$TMP/$name" >/dev/null 2>&1 || true; fi
  "$TMP/$name" --version 2>/dev/null | grep -q "$WANT" || { echo "✗ downloaded binary did not report $WANT" >&2; return 1; }
  mkdir -p "$FORK/dist" && mv "$TMP/$name" "$FORK/dist/komainu"
}

if $FROM_SOURCE || ! download; then
  progress build "Building Komainu from source (a few minutes the first time)"
  "$FORK/build.sh" >/dev/null
fi

progress install "Installing"
"$FORK/install.sh" >/dev/null
VERSION="$("${KOMAINU_BIN_DIR:-$HOME/.local/bin}/komainu" --version 2>/dev/null | sed 's/^komainu v//' || echo "$WANT")"
progress done "Komainu updated to $VERSION. Restart komainu to use it."
$TTY && echo "  (komainu service restart, if the background service is running)"
exit 0
