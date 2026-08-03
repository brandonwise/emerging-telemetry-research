#!/usr/bin/env bash
set -euo pipefail

research_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
research_label="ai.openclaw.telemetry-research-portal"
research_port="${ETR_PORTAL_PORT:-8088}"
research_uid="$(id -u)"
research_launch_agents="${HOME}/Library/LaunchAgents"
research_plist="${research_launch_agents}/${research_label}.plist"
research_logs="${HOME}/.openclaw/logs"
research_stdout="${research_logs}/telemetry-research-portal.log"
research_stderr="${research_logs}/telemetry-research-portal.error.log"
research_keychain_helper="${HOME}/.openclaw/bin/keychain-secret.sh"
research_tmp_plist="$(mktemp)"
research_auth_mode="${ETR_PORTAL_AUTH_MODE:-required}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auth)
      research_auth_mode="${2:?--auth requires required or disabled}"
      shift 2
      ;;
    --no-auth)
      research_auth_mode="disabled"
      shift
      ;;
    *)
      echo "usage: install-portal-service.sh [--auth required|disabled]" >&2
      exit 2
      ;;
  esac
done

cleanup() {
  rm -f "${research_tmp_plist}"
}
trap cleanup EXIT

if [[ ! "${research_port}" =~ ^[0-9]+$ ]] || (( research_port < 1024 || research_port > 65535 )); then
  echo "ETR_PORTAL_PORT must be an integer from 1024 to 65535" >&2
  exit 2
fi
if [[ "${research_auth_mode}" != "required" && "${research_auth_mode}" != "disabled" ]]; then
  echo "Portal authentication must be required or disabled" >&2
  exit 2
fi

mkdir -p "${research_launch_agents}" "${research_logs}" "${research_repo_root}/state"

if [[ "${research_auth_mode}" == "required" ]]; then
  if [[ ! -x "${research_keychain_helper}" ]]; then
    echo "OpenClaw Keychain helper is unavailable" >&2
    exit 1
  fi
  if ! /usr/bin/security find-generic-password \
    -a "clawdbot" \
    -s "ETR_PORTAL_ACCESS_TOKEN" >/dev/null 2>&1; then
    research_token="$(/usr/bin/openssl rand -hex 32)"
    /usr/bin/security add-generic-password \
      -a "clawdbot" \
      -s "ETR_PORTAL_ACCESS_TOKEN" \
      -w "${research_token}" >/dev/null
    unset research_token
  fi
fi

/usr/bin/plutil -create xml1 "${research_tmp_plist}"
/usr/bin/plutil -insert Label -string "${research_label}" "${research_tmp_plist}"
/usr/bin/plutil -insert ProgramArguments -json \
  "[\"/bin/bash\",\"${research_repo_root}/scripts/run-portal.sh\",\"--lan\",\"--port\",\"${research_port}\"]" \
  "${research_tmp_plist}"
/usr/bin/plutil -insert WorkingDirectory -string "${research_repo_root}" "${research_tmp_plist}"
/usr/bin/plutil -insert EnvironmentVariables -json \
  "{\"HOME\":\"${HOME}\",\"PATH\":\"/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin\",\"ETR_PORTAL_AUTH_MODE\":\"${research_auth_mode}\"}" \
  "${research_tmp_plist}"
/usr/bin/plutil -insert RunAtLoad -bool true "${research_tmp_plist}"
/usr/bin/plutil -insert KeepAlive -bool true "${research_tmp_plist}"
/usr/bin/plutil -insert ProcessType -string "Background" "${research_tmp_plist}"
/usr/bin/plutil -insert ThrottleInterval -integer 15 "${research_tmp_plist}"
/usr/bin/plutil -insert StandardOutPath -string "${research_stdout}" "${research_tmp_plist}"
/usr/bin/plutil -insert StandardErrorPath -string "${research_stderr}" "${research_tmp_plist}"
/usr/bin/plutil -lint "${research_tmp_plist}" >/dev/null
/usr/bin/install -m 600 "${research_tmp_plist}" "${research_plist}"

/bin/launchctl bootout "gui/${research_uid}/${research_label}" >/dev/null 2>&1 || true
research_bootstrapped="false"
for _research_attempt in $(seq 1 8); do
  if /bin/launchctl bootstrap "gui/${research_uid}" "${research_plist}" >/dev/null 2>&1; then
    research_bootstrapped="true"
    break
  fi
  sleep 0.25
done
if [[ "${research_bootstrapped}" != "true" ]]; then
  echo "Telemetry Research portal could not be loaded by launchd" >&2
  /bin/launchctl bootstrap "gui/${research_uid}" "${research_plist}"
  exit 1
fi

research_status=""
for _research_attempt in $(seq 1 30); do
  research_status="$(curl -sS -o /dev/null -w "%{http_code}" \
    "http://127.0.0.1:${research_port}/health" 2>/dev/null || true)"
  [[ "${research_status}" == "200" ]] && break
  sleep 0.25
done
if [[ "${research_status}" != "200" ]]; then
  echo "Telemetry Research portal failed its health check" >&2
  tail -40 "${research_stderr}" >&2 2>/dev/null || true
  exit 1
fi

cd "${research_repo_root}"
uv run emerging-telemetry-research analytics event \
  portal.service.enabled 1 service \
  --dimensions-json "{\"mode\":\"private_lan\",\"auth\":\"${research_auth_mode}\",\"port\":\"${research_port}\"}" \
  --database "${research_repo_root}/state/research.db" \
  --json >/dev/null

ETR_PORTAL_AUTH_MODE="${research_auth_mode}" "${research_repo_root}/scripts/portal-status.sh"
