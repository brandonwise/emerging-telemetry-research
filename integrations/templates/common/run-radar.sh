#!/usr/bin/env bash
set -euo pipefail

radar_config_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
radar_root="${RADAR_PROJECT_ROOT:-${radar_config_root}}"
while [[ ! -f "${radar_root}/pyproject.toml" && "${radar_root}" != "/" ]]; do
  radar_root="$(dirname "${radar_root}")"
done
if [[ ! -f "${radar_root}/pyproject.toml" ]]; then
  echo "Could not find the Threat Radar project root; set RADAR_PROJECT_ROOT" >&2
  exit 1
fi

if [[ -f "${radar_config_root}/radar.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "${radar_config_root}/radar.env"
  set +a
fi

cd "${radar_root}"
exec uv run threat-radar portable run --json "$@"
