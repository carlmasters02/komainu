#!/usr/bin/env bash
# Checks that an OpenCode release tag is genuine before Komainu builds from it, and prints the commit it points to.
#
#   fork/verify-upstream-tag.sh v2.4.1                 # clones OpenCode (no file contents) into a temporary folder
#   fork/verify-upstream-tag.sh v2.4.1 /path/to/clone  # uses an existing clone of OpenCode
#   EXPECT=<commit> fork/verify-upstream-tag.sh v2.4.1 # also fails if the tag no longer points at <commit>
#
# A tag is accepted when its commit is on OpenCode's default branch, or when it is OpenCode's release commit: exactly
# one commit named "release: <tag>" on top of the default branch that only changes "version" lines in package.json and
# bun.lock files and adds to CHANGELOG.md. Anything else (a tag on some other branch, a release commit that changes
# code, a tag that moved) is refused, so a tampered tag can't get built and shipped to Komainu users.
set -euo pipefail

TAG="${1:?usage: fork/verify-upstream-tag.sh <tag> [opencode clone]}"
REPO="${2:-}"
fail() { echo "✗ OpenCode $TAG failed the authenticity check: $*" >&2; exit 1; }

if [ -z "$REPO" ]; then
  REPO="$(mktemp -d)"
  trap 'rm -rf "$REPO"' EXIT
  git clone -q --filter=blob:none --no-checkout https://github.com/anomalyco/opencode "$REPO"
fi
cd "$REPO"

COMMIT="$(git rev-parse -q --verify "refs/tags/$TAG^{commit}")" || fail "no such tag"
DEFAULT="$(git symbolic-ref --short refs/remotes/origin/HEAD)"
DEFAULT="${DEFAULT#origin/}"

if [ -n "${EXPECT:-}" ] && [ "$COMMIT" != "$EXPECT" ]; then
  fail "the tag moved: Komainu adopted $EXPECT, but it now points at $COMMIT"
fi

if ! git merge-base --is-ancestor "$COMMIT" "origin/$DEFAULT"; then
  [ "$(git log -1 --format=%s "$COMMIT")" = "release: $TAG" ] || fail "it isn't on $DEFAULT and isn't a release commit"
  [ "$(git rev-list --count "$COMMIT" "^origin/$DEFAULT")" = 1 ] || fail "it is more than one commit away from $DEFAULT"
  git merge-base --is-ancestor "$COMMIT^" "origin/$DEFAULT" || fail "the release commit isn't built on $DEFAULT"
  while IFS= read -r file; do
    case "$(basename "$file")" in
      package.json | bun.lock | CHANGELOG.md) ;;
      *) fail "the release commit changes $file" ;;
    esac
  done < <(git diff --no-renames --name-only "$COMMIT^" "$COMMIT")
  changed="$(git diff --no-renames "$COMMIT^" "$COMMIT" -- . ':!CHANGELOG.md' | grep '^[-+]' | grep -v '^+++ \|^--- ' \
    | grep -vE '^[-+][[:space:]]*"version": "[0-9][0-9A-Za-z.+-]*",?$' || true)"
  [ -z "$changed" ] || fail "the release commit changes more than version numbers: $(head -c 300 <<< "$changed")"
  removed="$(git diff --no-renames "$COMMIT^" "$COMMIT" -- CHANGELOG.md | grep '^-' | grep -v '^--- ' || true)"
  [ -z "$removed" ] || fail "the release commit removes changelog lines"
fi

echo "$COMMIT"
