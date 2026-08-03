#!/usr/bin/env bash
set -euo pipefail

research_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
research_label="ai.openclaw.telemetry-research-portal"
research_plist="${HOME}/Library/LaunchAgents/${research_label}.plist"
research_uid="$(id -u)"
research_purge_token="false"

if [[ "${1:-}" == "--purge-token" ]]; then
  research_purge_token="true"
elif [[ $# -gt 0 ]]; then
  echo "usage: uninstall-portal-service.sh [--purge-token]" >&2
  exit 2
fi

/bin/launchctl bootout "gui/${research_uid}/${research_label}" >/dev/null 2>&1 || true
if [[ -f "${research_plist}" ]]; then
  research_trash="${HOME}/.Trash/${research_label}.$(date +%Y%m%d%H%M%S).plist"
  mv "${research_plist}" "${research_trash}"
  echo "LaunchAgent moved to ${research_trash}"
fi
if [[ "${research_purge_token}" == "true" ]]; then
  /usr/bin/security delete-generic-password \
    -a "clawdbot" \
    -s "ETR_PORTAL_ACCESS_TOKEN" >/dev/null 2>&1 || true
fi

cd "${research_repo_root}"
uv run emerging-telemetry-research analytics event \
  portal.service.disabled 1 service \
  --dimensions-json '{"mode":"private_lan"}' \
  --database "${research_repo_root}/state/research.db" \
  --json >/dev/null

printf '{"label":"%s","loaded":false,"token_preserved":%s}\n' \
  "${research_label}" \
  "$([[ "${research_purge_token}" == "true" ]] && echo false || echo true)"
