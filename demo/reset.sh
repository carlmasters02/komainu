#!/usr/bin/env bash
# Resets ~/komainu-demo between rehearsals: removes files the agent created and archives the audit log.
set -euo pipefail
cd "${1:-$HOME/komainu-demo}"
rm -rf cache.py legacy.py download.py app.py __pycache__
if [ -f .komainu/audit.jsonl ]; then
  mv .komainu/audit.jsonl ".komainu/audit-$(date +%Y%m%d-%H%M%S).jsonl"
fi
opencode service restart >/dev/null
echo "Demo reset. Start fresh sessions with: cd $(pwd) && opencode"
