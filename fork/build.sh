#!/usr/bin/env bash
# Builds the `komainu` binary: upstream OpenCode at the pinned tag + Komainu's patches.
#   fork/build.sh            # build the tag in fork/UPSTREAM
#   fork/build.sh v2.4.0     # try a newer upstream tag (used by the sync workflow)
set -euo pipefail

FORK="$(cd "$(dirname "$0")" && pwd)"
TAG="${1:-$(cat "$FORK/UPSTREAM")}"
SRC="$FORK/.work/opencode-$TAG"

if [ ! -d "$SRC/.git" ]; then
  echo "→ fetching OpenCode $TAG"
  git clone -q --depth 1 --branch "$TAG" https://github.com/anomalyco/opencode "$SRC"
fi

cd "$SRC"
echo "→ resetting to clean $TAG"
git am --abort >/dev/null 2>&1 || true
git reset -q --hard "$(git rev-list -n1 "$TAG")"
git clean -qfd            # keeps ignored files (node_modules) for faster rebuilds

echo "→ applying $(ls "$FORK"/patches/*.patch | wc -l) Komainu patches"
if ! git -c user.name=komainu -c user.email=build@localhost am -q --3way "$FORK"/patches/*.patch; then
  git am --abort || true
  echo "✗ patches no longer apply cleanly to $TAG; they need updating (see fork/README.md)" >&2
  exit 2
fi

echo "→ installing dependencies"
bun install >/dev/null 2>&1 || echo "  (some optional packages failed to install; continuing)"

echo "→ building"
cd packages/cli
OPENCODE_VERSION="${TAG#v}-komainu" bun run script/build.ts --single --skip-web-ui --skip-install >/dev/null
mkdir -p "$FORK/dist"
cp dist/*/bin/komainu "$FORK/dist/komainu"
"$FORK/dist/komainu" --version
echo "✓ built fork/dist/komainu"
