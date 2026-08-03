#!/usr/bin/env bash
set -euo pipefail

research_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
research_label="ai.openclaw.telemetry-research-portal"
research_port="${ETR_PORTAL_PORT:-8088}"
research_uid="$(id -u)"
research_loaded="false"
research_healthy="false"
research_ip=""
research_auth_mode="${ETR_PORTAL_AUTH_MODE:-}"
research_plist="${HOME}/Library/LaunchAgents/${research_label}.plist"

if [[ -z "${research_auth_mode}" && -f "${research_plist}" ]]; then
  research_auth_mode="$(/usr/bin/plutil -extract \
    EnvironmentVariables.ETR_PORTAL_AUTH_MODE raw -o - "${research_plist}" 2>/dev/null || true)"
fi
research_auth_mode="${research_auth_mode:-required}"

if /bin/launchctl print "gui/${research_uid}/${research_label}" >/dev/null 2>&1; then
  research_loaded="true"
fi
if [[ "$(curl -sS -o /dev/null -w "%{http_code}" \
  "http://127.0.0.1:${research_port}/health" 2>/dev/null || true)" == "200" ]]; then
  research_healthy="true"
fi
if command -v ipconfig >/dev/null 2>&1; then
  for research_interface in en0 en1 en2 en3; do
    research_ip="$(ipconfig getifaddr "${research_interface}" 2>/dev/null || true)"
    [[ -n "${research_ip}" ]] && break
  done
elif command -v hostname >/dev/null 2>&1; then
  research_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
research_ip="${research_ip:-private-ip}"

research_reports=0
research_events=0
if [[ -f "${research_repo_root}/state/research.db" ]]; then
  research_reports="$(sqlite3 "${research_repo_root}/state/research.db" \
    "SELECT COUNT(*) FROM analytics_reports;" 2>/dev/null || echo 0)"
  research_events="$(sqlite3 "${research_repo_root}/state/research.db" \
    "SELECT COUNT(*) FROM analytics_events;" 2>/dev/null || echo 0)"
fi

printf '{"label":"%s","loaded":%s,"healthy":%s,"url":"http://%s:%s","auth":"%s","reports":%s,"events":%s}\n' \
  "${research_label}" \
  "${research_loaded}" \
  "${research_healthy}" \
  "${research_ip}" \
  "${research_port}" \
  "${research_auth_mode}" \
  "${research_reports}" \
  "${research_events}"

if [[ "${research_loaded}" != "true" || "${research_healthy}" != "true" ]]; then
  exit 1
fi
