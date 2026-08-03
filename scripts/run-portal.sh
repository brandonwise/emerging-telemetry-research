#!/usr/bin/env bash
set -euo pipefail

radar_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
radar_host="127.0.0.1"
radar_port="${RADAR_PORTAL_PORT:-8088}"
radar_lan="false"
radar_certfile=""
radar_keyfile=""
radar_auth_mode="${RADAR_PORTAL_AUTH_MODE:-auto}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lan)
      radar_host="0.0.0.0"
      radar_lan="true"
      shift
      ;;
    --port)
      radar_port="${2:?--port requires a value}"
      shift 2
      ;;
    --certfile)
      radar_certfile="${2:?--certfile requires a value}"
      shift 2
      ;;
    --keyfile)
      radar_keyfile="${2:?--keyfile requires a value}"
      shift 2
      ;;
    --auth)
      radar_auth_mode="${2:?--auth requires required or disabled}"
      shift 2
      ;;
    --no-auth)
      radar_auth_mode="disabled"
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "${radar_auth_mode}" != "auto" \
  && "${radar_auth_mode}" != "required" \
  && "${radar_auth_mode}" != "disabled" ]]; then
  echo "Portal authentication must be auto, required, or disabled" >&2
  exit 2
fi

if [[ ! "${radar_port}" =~ ^[0-9]+$ ]] || (( radar_port < 1024 || radar_port > 65535 )); then
  echo "Portal port must be an integer from 1024 to 65535" >&2
  exit 2
fi

if [[ -n "${radar_certfile}" || -n "${radar_keyfile}" ]]; then
  if [[ ! -f "${radar_certfile}" || ! -f "${radar_keyfile}" ]]; then
    echo "Both --certfile and --keyfile must reference readable files" >&2
    exit 2
  fi
  export RADAR_PORTAL_SECURE_COOKIE="true"
fi

if [[ "${radar_lan}" == "true" ]]; then
  export RADAR_PORTAL_LAN_MODE="true"
fi
export RADAR_PORTAL_AUTH_MODE="${radar_auth_mode}"

radar_token_required="false"
if [[ "${radar_auth_mode}" == "required" \
  || ( "${radar_auth_mode}" == "auto" && "${radar_lan}" == "true" ) ]]; then
  radar_token_required="true"
fi
if [[ "${radar_auth_mode}" == "disabled" ]]; then
  unset RADAR_PORTAL_ACCESS_TOKEN
elif [[ "${radar_token_required}" == "true" ]]; then
  radar_portal_token="${RADAR_PORTAL_ACCESS_TOKEN:-}"
  if [[ -z "${radar_portal_token}" ]]; then
    radar_keychain_helper="${HOME}/.openclaw/bin/keychain-secret.sh"
    if [[ -x "${radar_keychain_helper}" ]]; then
      radar_portal_token="$("${radar_keychain_helper}" RADAR_PORTAL_ACCESS_TOKEN 2>/dev/null || true)"
    fi
  fi
  if [[ ${#radar_portal_token} -lt 20 ]]; then
    echo "Portal authentication requires RADAR_PORTAL_ACCESS_TOKEN with at least 20 characters" >&2
    exit 2
  fi
  export RADAR_PORTAL_ACCESS_TOKEN="${radar_portal_token}"
fi

export RADAR_PORTAL_ANALYTICS_DB="${RADAR_PORTAL_ANALYTICS_DB:-${radar_repo_root}/state/radar.db}"
export RADAR_PORTAL_REPORTS_ROOT="${RADAR_PORTAL_REPORTS_ROOT:-${radar_repo_root}/reports/generated}"
export RADAR_PORTAL_MISSIONS_ROOT="${RADAR_PORTAL_MISSIONS_ROOT:-${radar_repo_root}/missions}"
export RADAR_PORTAL_MISSION_REPORTS_ROOT="${RADAR_PORTAL_MISSION_REPORTS_ROOT:-${radar_repo_root}/reports/missions}"

radar_protocol="http"
radar_tls_args=()
if [[ -n "${radar_certfile}" ]]; then
  radar_protocol="https"
  radar_tls_args=(--ssl-certfile "${radar_certfile}" --ssl-keyfile "${radar_keyfile}")
fi

if [[ "${radar_lan}" == "true" ]]; then
  radar_ip=""
  if command -v ipconfig >/dev/null 2>&1; then
    for radar_interface in en0 en1 en2 en3; do
      radar_ip="$(ipconfig getifaddr "${radar_interface}" 2>/dev/null || true)"
      [[ -n "${radar_ip}" ]] && break
    done
  elif command -v hostname >/dev/null 2>&1; then
    radar_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  radar_ip="${radar_ip:-<private-ip>}"
  echo "Outcome Radar portal: ${radar_protocol}://${radar_ip}:${radar_port}" >&2
else
  echo "Outcome Radar portal: ${radar_protocol}://127.0.0.1:${radar_port}" >&2
fi

cd "${radar_repo_root}"
if [[ -n "${radar_certfile}" ]]; then
  exec uv run uvicorn apps.portal.main:app \
    --host "${radar_host}" \
    --port "${radar_port}" \
    --no-server-header \
    "${radar_tls_args[@]}"
fi
exec uv run uvicorn apps.portal.main:app \
  --host "${radar_host}" \
  --port "${radar_port}" \
  --no-server-header
