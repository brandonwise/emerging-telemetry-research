#!/usr/bin/env bash
set -euo pipefail

radar_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
radar_label="ai.openclaw.threat-radar-portal"
radar_port="${RADAR_PORTAL_PORT:-8088}"
radar_uid="$(id -u)"
radar_launch_agents="${HOME}/Library/LaunchAgents"
radar_plist="${radar_launch_agents}/${radar_label}.plist"
radar_logs="${HOME}/.openclaw/logs"
radar_stdout="${radar_logs}/threat-radar-portal.log"
radar_stderr="${radar_logs}/threat-radar-portal.error.log"
radar_keychain_helper="${HOME}/.openclaw/bin/keychain-secret.sh"
radar_tmp_plist="$(mktemp)"
radar_auth_mode="${RADAR_PORTAL_AUTH_MODE:-required}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auth)
      radar_auth_mode="${2:?--auth requires required or disabled}"
      shift 2
      ;;
    --no-auth)
      radar_auth_mode="disabled"
      shift
      ;;
    *)
      echo "usage: install-portal-service.sh [--auth required|disabled]" >&2
      exit 2
      ;;
  esac
done

cleanup() {
  rm -f "${radar_tmp_plist}"
}
trap cleanup EXIT

if [[ ! "${radar_port}" =~ ^[0-9]+$ ]] || (( radar_port < 1024 || radar_port > 65535 )); then
  echo "RADAR_PORTAL_PORT must be an integer from 1024 to 65535" >&2
  exit 2
fi
if [[ "${radar_auth_mode}" != "required" && "${radar_auth_mode}" != "disabled" ]]; then
  echo "Portal authentication must be required or disabled" >&2
  exit 2
fi

mkdir -p "${radar_launch_agents}" "${radar_logs}" "${radar_repo_root}/state"

if [[ "${radar_auth_mode}" == "required" ]]; then
  if [[ ! -x "${radar_keychain_helper}" ]]; then
    echo "OpenClaw Keychain helper is unavailable" >&2
    exit 1
  fi
  if ! /usr/bin/security find-generic-password \
    -a "clawdbot" \
    -s "RADAR_PORTAL_ACCESS_TOKEN" >/dev/null 2>&1; then
    radar_token="$(/usr/bin/openssl rand -hex 32)"
    /usr/bin/security add-generic-password \
      -a "clawdbot" \
      -s "RADAR_PORTAL_ACCESS_TOKEN" \
      -w "${radar_token}" >/dev/null
    unset radar_token
  fi
fi

/usr/bin/plutil -create xml1 "${radar_tmp_plist}"
/usr/bin/plutil -insert Label -string "${radar_label}" "${radar_tmp_plist}"
/usr/bin/plutil -insert ProgramArguments -json \
  "[\"/bin/bash\",\"${radar_repo_root}/scripts/run-portal.sh\",\"--lan\",\"--port\",\"${radar_port}\"]" \
  "${radar_tmp_plist}"
/usr/bin/plutil -insert WorkingDirectory -string "${radar_repo_root}" "${radar_tmp_plist}"
/usr/bin/plutil -insert EnvironmentVariables -json \
  "{\"HOME\":\"${HOME}\",\"PATH\":\"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\",\"RADAR_PORTAL_AUTH_MODE\":\"${radar_auth_mode}\"}" \
  "${radar_tmp_plist}"
/usr/bin/plutil -insert RunAtLoad -bool true "${radar_tmp_plist}"
/usr/bin/plutil -insert KeepAlive -bool true "${radar_tmp_plist}"
/usr/bin/plutil -insert ProcessType -string "Background" "${radar_tmp_plist}"
/usr/bin/plutil -insert ThrottleInterval -integer 15 "${radar_tmp_plist}"
/usr/bin/plutil -insert StandardOutPath -string "${radar_stdout}" "${radar_tmp_plist}"
/usr/bin/plutil -insert StandardErrorPath -string "${radar_stderr}" "${radar_tmp_plist}"
/usr/bin/plutil -lint "${radar_tmp_plist}" >/dev/null
/usr/bin/install -m 600 "${radar_tmp_plist}" "${radar_plist}"

/bin/launchctl bootout "gui/${radar_uid}/${radar_label}" >/dev/null 2>&1 || true
radar_bootstrapped="false"
for _radar_attempt in $(seq 1 8); do
  if /bin/launchctl bootstrap "gui/${radar_uid}" "${radar_plist}" >/dev/null 2>&1; then
    radar_bootstrapped="true"
    break
  fi
  sleep 0.25
done
if [[ "${radar_bootstrapped}" != "true" ]]; then
  echo "Threat Radar portal could not be loaded by launchd" >&2
  /bin/launchctl bootstrap "gui/${radar_uid}" "${radar_plist}"
  exit 1
fi

radar_status=""
for _radar_attempt in $(seq 1 30); do
  radar_status="$(curl -sS -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${radar_port}/health" 2>/dev/null || true)"
  [[ "${radar_status}" == "200" ]] && break
  sleep 0.25
done
if [[ "${radar_status}" != "200" ]]; then
  echo "Threat Radar portal failed its health check" >&2
  tail -40 "${radar_stderr}" >&2 2>/dev/null || true
  exit 1
fi

cd "${radar_repo_root}"
uv run threat-radar analytics event \
  portal.service.enabled 1 service \
  --dimensions-json "{\"mode\":\"private_lan\",\"auth\":\"${radar_auth_mode}\",\"port\":\"${radar_port}\"}" \
  --database "${radar_repo_root}/state/radar.db" \
  --json >/dev/null

RADAR_PORTAL_AUTH_MODE="${radar_auth_mode}" "${radar_repo_root}/scripts/portal-status.sh"
