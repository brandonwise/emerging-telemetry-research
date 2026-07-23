#!/usr/bin/env bash
set -euo pipefail

ORG="${1:-}"
REPO_NAME="${2:-openclaw-emerging-threat-radar}"

if [[ -z "$ORG" ]]; then
  echo "Usage: $0 <github-org-or-user> [repo-name]" >&2
  exit 2
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI (gh) is required." >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -d .git ]]; then
  git init -b main
fi

git add .
if ! git diff --cached --quiet; then
  git commit -m "Initial Threat Radar architecture scaffold"
fi

gh repo create "$ORG/$REPO_NAME" \
  --private \
  --source=. \
  --remote=origin \
  --push \
  --description "Proactive, evidence-backed emerging cyber-threat radar for OpenClaw"

echo "Created private repository: $ORG/$REPO_NAME"
echo "Next: configure branch protection, environments, CODEOWNERS teams, and required checks."
