#!/usr/bin/env bash
set -euo pipefail

radar_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
radar_label="ai.openclaw.threat-radar-portal"
radar_port="${RADAR_PORTAL_PORT:-8088}"
radar_uid="$(id -u)"
radar_loaded="false"
radar_healthy="false"
radar_ip=""

if /bin/launchctl print "gui/${radar_uid}/${radar_label}" >/dev/null 2>&1; then
  radar_loaded="true"
fi
if [[ "$(curl -sS -o /dev/null -w "%{http_code}" \
  "http://127.0.0.1:${radar_port}/health" 2>/dev/null || true)" == "200" ]]; then
  radar_healthy="true"
fi
if command -v ipconfig >/dev/null 2>&1; then
  for radar_interface in en0 en1 en2 en3; do
    radar_ip="$(ipconfig getifaddr "${radar_interface}" 2>/dev/null || true)"
    [[ -n "${radar_ip}" ]] && break
  done
elif command -v hostname >/dev/null 2>&1; then
  radar_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
fi
radar_ip="${radar_ip:-private-ip}"

radar_reports=0
radar_events=0
if [[ -f "${radar_repo_root}/state/radar.db" ]]; then
  radar_reports="$(sqlite3 "${radar_repo_root}/state/radar.db" \
    "SELECT COUNT(*) FROM analytics_reports;" 2>/dev/null || echo 0)"
  radar_events="$(sqlite3 "${radar_repo_root}/state/radar.db" \
    "SELECT COUNT(*) FROM analytics_events;" 2>/dev/null || echo 0)"
fi

printf '{"label":"%s","loaded":%s,"healthy":%s,"url":"http://%s:%s","reports":%s,"events":%s}\n' \
  "${radar_label}" \
  "${radar_loaded}" \
  "${radar_healthy}" \
  "${radar_ip}" \
  "${radar_port}" \
  "${radar_reports}" \
  "${radar_events}"

if [[ "${radar_loaded}" != "true" || "${radar_healthy}" != "true" ]]; then
  exit 1
fi
