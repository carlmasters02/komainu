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
FROM_SOURCE=false
WANT=""
for arg in "$@"; do
  case "$arg" in
    --source) FROM_SOURCE=true ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) WANT="${arg#v}" ;;
  esac
done

# One update at a time (several komainu windows may offer it at once).
mkdir -p "$STATE"
LOCK="$STATE/update.lock"
if ! mkdir "$LOCK" 2>/dev/null; then
  if [ -n "$(find "$LOCK" -maxdepth 0 -mmin +30 2>/dev/null)" ]; then rm -rf "$LOCK"; mkdir "$LOCK"
  else echo "✗ another Komainu update is running (remove $LOCK if it is stuck)" >&2; exit 1; fi
fi
TMP="$(mktemp -d)"
trap 'rm -rf "$LOCK" "$TMP"' EXIT

if [ -z "$WANT" ]; then
  WANT="$(curl -fsSL -H 'accept: application/vnd.github+json' \
    "https://api.github.com/repos/$OWNER_REPO/releases/latest" 2>/dev/null \
    | sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1 || true)"
fi

if [ -d "$REPO/.git" ]; then
  echo "→ pulling the latest Komainu code"
  if ! git -C "$REPO" pull --ff-only --quiet; then
    echo "✗ could not fast-forward $REPO (local changes or a diverged branch). Commit or stash them, then retry." >&2
    exit 1
  fi
fi
[ -n "$WANT" ] || WANT="$(sed 's/^v//' "$FORK/UPSTREAM")-komainu"
echo "→ target version $WANT (OpenCode $(cat "$FORK/UPSTREAM"))"

echo "→ installing plugin dependencies"
(cd "$REPO" && bun install >/dev/null)

case "$(uname -s)" in Linux) OS=linux ;; Darwin) OS=darwin ;; *) OS="" ;; esac
case "$(uname -m)" in x86_64|amd64) ARCH=x64 ;; aarch64|arm64) ARCH=arm64 ;; *) ARCH="" ;; esac

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

download() {
  [ -n "$OS" ] && [ -n "$ARCH" ] || return 1
  local base="${KOMAINU_RELEASE_BASE:-https://github.com/$OWNER_REPO/releases/download}/v$WANT"
  local asset="komainu-$OS-$ARCH"
  echo "→ downloading $asset ($WANT)"
  curl -fsSL -o "$TMP/$asset" "$base/$asset" || return 1
  curl -fsSL -o "$TMP/SHA256SUMS" "$base/SHA256SUMS" || return 1
  local expected; expected="$(awk -v a="$asset" '$2 == a || $2 == "*"a {print $1}' "$TMP/SHA256SUMS")"
  if [ -z "$expected" ] || [ "$(sha256 "$TMP/$asset")" != "$expected" ]; then
    echo "✗ checksum mismatch for $asset; not installing it" >&2; return 1
  fi
  chmod 755 "$TMP/$asset"
  # Apple Silicon refuses unsigned binaries; an ad-hoc signature is enough for a binary you downloaded yourself.
  [ "$OS" = darwin ] && command -v codesign >/dev/null && codesign --force --sign - "$TMP/$asset" >/dev/null 2>&1
  "$TMP/$asset" --version 2>/dev/null | grep -q "$WANT" || { echo "✗ downloaded binary did not report $WANT" >&2; return 1; }
  mkdir -p "$FORK/dist" && mv "$TMP/$asset" "$FORK/dist/komainu"
}

if $FROM_SOURCE || ! download; then
  $FROM_SOURCE || echo "→ no prebuilt binary for this machine; building from source instead"
  "$FORK/build.sh"
fi

"$FORK/install.sh"
echo "✓ Komainu updated to $("${KOMAINU_BIN_DIR:-$HOME/.local/bin}/komainu" --version 2>/dev/null | sed "s/^komainu v//" || echo "$WANT")."
echo "  Restart komainu to use it (komainu service restart, if the background service is running)."
