#!/usr/bin/env bash
set -euo pipefail

research_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
research_host="127.0.0.1"
research_port="${ETR_PORTAL_PORT:-8088}"
research_lan="false"
research_certfile=""
research_keyfile=""
research_auth_mode="${ETR_PORTAL_AUTH_MODE:-auto}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --lan)
      research_host="0.0.0.0"
      research_lan="true"
      shift
      ;;
    --port)
      research_port="${2:?--port requires a value}"
      shift 2
      ;;
    --certfile)
      research_certfile="${2:?--certfile requires a value}"
      shift 2
      ;;
    --keyfile)
      research_keyfile="${2:?--keyfile requires a value}"
      shift 2
      ;;
    --auth)
      research_auth_mode="${2:?--auth requires required or disabled}"
      shift 2
      ;;
    --no-auth)
      research_auth_mode="disabled"
      shift
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
done

if [[ "${research_auth_mode}" != "auto" \
  && "${research_auth_mode}" != "required" \
  && "${research_auth_mode}" != "disabled" ]]; then
  echo "Portal authentication must be auto, required, or disabled" >&2
  exit 2
fi

if [[ ! "${research_port}" =~ ^[0-9]+$ ]] || (( research_port < 1024 || research_port > 65535 )); then
  echo "Portal port must be an integer from 1024 to 65535" >&2
  exit 2
fi

if [[ -n "${research_certfile}" || -n "${research_keyfile}" ]]; then
  if [[ ! -f "${research_certfile}" || ! -f "${research_keyfile}" ]]; then
    echo "Both --certfile and --keyfile must reference readable files" >&2
    exit 2
  fi
  export ETR_PORTAL_SECURE_COOKIE="true"
fi

if [[ "${research_lan}" == "true" ]]; then
  export ETR_PORTAL_LAN_MODE="true"
fi
export ETR_PORTAL_AUTH_MODE="${research_auth_mode}"

research_token_required="false"
if [[ "${research_auth_mode}" == "required" \
  || ( "${research_auth_mode}" == "auto" && "${research_lan}" == "true" ) ]]; then
  research_token_required="true"
fi
if [[ "${research_auth_mode}" == "disabled" ]]; then
  unset ETR_PORTAL_ACCESS_TOKEN
elif [[ "${research_token_required}" == "true" ]]; then
  research_portal_token="${ETR_PORTAL_ACCESS_TOKEN:-}"
  if [[ -z "${research_portal_token}" ]]; then
    research_keychain_helper="${HOME}/.openclaw/bin/keychain-secret.sh"
    if [[ -x "${research_keychain_helper}" ]]; then
      research_portal_token="$("${research_keychain_helper}" ETR_PORTAL_ACCESS_TOKEN 2>/dev/null || true)"
    fi
  fi
  if [[ ${#research_portal_token} -lt 20 ]]; then
    echo "Portal authentication requires ETR_PORTAL_ACCESS_TOKEN with at least 20 characters" >&2
    exit 2
  fi
  export ETR_PORTAL_ACCESS_TOKEN="${research_portal_token}"
fi

export ETR_PORTAL_ANALYTICS_DB="${ETR_PORTAL_ANALYTICS_DB:-${research_repo_root}/state/research.db}"
export ETR_PORTAL_REPORTS_ROOT="${ETR_PORTAL_REPORTS_ROOT:-${research_repo_root}/reports/generated}"
export ETR_PORTAL_MISSIONS_ROOT="${ETR_PORTAL_MISSIONS_ROOT:-${research_repo_root}/missions}"
export ETR_PORTAL_MISSION_REPORTS_ROOT="${ETR_PORTAL_MISSION_REPORTS_ROOT:-${research_repo_root}/reports/missions}"

research_protocol="http"
research_tls_args=()
if [[ -n "${research_certfile}" ]]; then
  research_protocol="https"
  research_tls_args=(--ssl-certfile "${research_certfile}" --ssl-keyfile "${research_keyfile}")
fi

if [[ "${research_lan}" == "true" ]]; then
  research_ip=""
  if command -v ipconfig >/dev/null 2>&1; then
    for research_interface in en0 en1 en2 en3; do
      research_ip="$(ipconfig getifaddr "${research_interface}" 2>/dev/null || true)"
      [[ -n "${research_ip}" ]] && break
    done
  elif command -v hostname >/dev/null 2>&1; then
    research_ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  fi
  research_ip="${research_ip:-<private-ip>}"
  echo "Emerging Telemetry Research portal: ${research_protocol}://${research_ip}:${research_port}" >&2
else
  echo "Emerging Telemetry Research portal: ${research_protocol}://127.0.0.1:${research_port}" >&2
fi

cd "${research_repo_root}"
if [[ -n "${research_certfile}" ]]; then
  exec uv run uvicorn apps.portal.main:app \
    --host "${research_host}" \
    --port "${research_port}" \
    --no-server-header \
    "${research_tls_args[@]}"
fi
exec uv run uvicorn apps.portal.main:app \
  --host "${research_host}" \
  --port "${research_port}" \
  --no-server-header
