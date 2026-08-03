#!/usr/bin/env bash
set -euo pipefail

radar_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
radar_label="ai.openclaw.threat-radar-portal"
radar_plist="${HOME}/Library/LaunchAgents/${radar_label}.plist"
radar_uid="$(id -u)"
radar_purge_token="false"

if [[ "${1:-}" == "--purge-token" ]]; then
  radar_purge_token="true"
elif [[ $# -gt 0 ]]; then
  echo "usage: uninstall-portal-service.sh [--purge-token]" >&2
  exit 2
fi

/bin/launchctl bootout "gui/${radar_uid}/${radar_label}" >/dev/null 2>&1 || true
if [[ -f "${radar_plist}" ]]; then
  radar_trash="${HOME}/.Trash/${radar_label}.$(date +%Y%m%d%H%M%S).plist"
  mv "${radar_plist}" "${radar_trash}"
  echo "LaunchAgent moved to ${radar_trash}"
fi
if [[ "${radar_purge_token}" == "true" ]]; then
  /usr/bin/security delete-generic-password \
    -a "clawdbot" \
    -s "RADAR_PORTAL_ACCESS_TOKEN" >/dev/null 2>&1 || true
fi

cd "${radar_repo_root}"
uv run outcome-radar analytics event \
  portal.service.disabled 1 service \
  --dimensions-json '{"mode":"private_lan"}' \
  --database "${radar_repo_root}/state/radar.db" \
  --json >/dev/null

printf '{"label":"%s","loaded":false,"token_preserved":%s}\n' \
  "${radar_label}" \
  "$([[ "${radar_purge_token}" == "true" ]] && echo false || echo true)"
