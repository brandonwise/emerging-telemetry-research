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

cd "${radar_root}"
radar_env_args=()
if [[ -f "${radar_config_root}/radar.env" ]]; then
  radar_env_args=(--env-file "${radar_config_root}/radar.env")
fi
exec uv run outcome-radar "${radar_env_args[@]}" portable run --json "$@"
