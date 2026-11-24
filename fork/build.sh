#!/usr/bin/env bash
# Builds the `komainu` binary: upstream OpenCode at the pinned tag + Komainu's patches.
#   fork/build.sh            # build the tag in fork/UPSTREAM
#   fork/build.sh v2.4.0     # try a newer upstream tag (used by the sync workflow)
# Optional env: KOMAINU_VERSION (version baked into the binary, default <tag>-komainu, plus .<n> from
#               fork/REVISION when building the pinned tag),
#               OPENCODE_TARGET (cross-build, e.g. darwin-arm64; default: this machine)
set -euo pipefail

export PATH="${BUN_INSTALL:-$HOME/.bun}/bin:$PATH"   # finds Bun even before the terminal is reopened
command -v bun >/dev/null || { echo "✗ Bun isn't installed. Install it with: curl -fsSL https://bun.sh/install | bash   then run this again." >&2; exit 1; }

FORK="$(cd "$(dirname "$0")" && pwd)"
TAG="${1:-$(cat "$FORK/UPSTREAM")}"
SRC="$FORK/.work/opencode-$TAG"
VERSION="${TAG#v}-komainu"
# Same version as the published release, so a source build is not offered the release it already is.
if [ "$TAG" = "$(cat "$FORK/UPSTREAM")" ] && [ -s "$FORK/REVISION" ]; then VERSION="$VERSION.$(cat "$FORK/REVISION")"; fi
# The exact OpenCode commit Komainu adopted for this tag (fork/verify-upstream-tag.sh checked it), so a tag moved
# upstream later can't change what gets built.
# fork/UPSTREAM_COMMIT holds "<tag> <commit>"; it only applies to that tag.
PIN=""
if [ -s "$FORK/UPSTREAM_COMMIT" ]; then
  read -r PIN_TAG PIN_COMMIT < "$FORK/UPSTREAM_COMMIT" || true
  if [ "${PIN_TAG:-}" = "$TAG" ]; then PIN="${PIN_COMMIT:-}"; fi
fi

if [ ! -d "$SRC/.git" ]; then
  echo "→ fetching OpenCode $TAG"
  git clone -q --depth 1 --branch "$TAG" https://github.com/anomalyco/opencode "$SRC"
fi

cd "$SRC"
echo "→ resetting to clean $TAG"
git am --abort >/dev/null 2>&1 || true
TAG_COMMIT="$(git rev-list -n1 "$TAG")"
if [ -n "$PIN" ] && [ "$TAG_COMMIT" != "$PIN" ]; then
  echo "✗ OpenCode $TAG now points at $TAG_COMMIT, not the commit Komainu adopted ($PIN)." >&2
  echo "  Refusing to build it. Please report this: https://github.com/carlmasters02/komainu/issues" >&2
  exit 1
fi
git reset -q --hard "$TAG_COMMIT"
git clean -qfd            # keeps ignored files (node_modules) for faster rebuilds

echo "→ applying $(ls "$FORK"/patches/*.patch | wc -l) Komainu patches"
if ! git -c user.name=komainu -c user.email=build@localhost am -q --3way "$FORK"/patches/*.patch; then
  git am --abort || true
  echo "✗ patches no longer apply cleanly to $TAG; they need updating (see fork/README.md)" >&2
  exit 2
fi

echo "→ installing dependencies"
# Cross-builds need every platform's native packages (pty, TUI renderer), not just this machine's.
if [ -n "${OPENCODE_TARGET:-}" ]; then INSTALL_ARGS=(--os="*" --cpu="*"); else INSTALL_ARGS=(); fi
bun install ${INSTALL_ARGS[@]+"${INSTALL_ARGS[@]}"} >/dev/null 2>&1 || echo "  (some optional packages failed to install; continuing)"

echo "→ building"
cd packages/cli
rm -rf dist
if [ -n "${OPENCODE_TARGET:-}" ]; then
  OPENCODE_VERSION="${KOMAINU_VERSION:-$VERSION}" bun run script/build.ts --skip-web-ui --skip-install >/dev/null
else
  OPENCODE_VERSION="${KOMAINU_VERSION:-$VERSION}" bun run script/build.ts --single --skip-web-ui --skip-install >/dev/null
fi
mkdir -p "$FORK/dist"
cp dist/*/bin/komainu "$FORK/dist/komainu"
[ -n "${OPENCODE_TARGET:-}" ] || "$FORK/dist/komainu" --version
echo "✓ built fork/dist/komainu"
