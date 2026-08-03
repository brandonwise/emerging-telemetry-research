#!/usr/bin/env bash
set -euo pipefail

research_config_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
research_root="${ETR_PROJECT_ROOT:-${research_config_root}}"
while [[ ! -f "${research_root}/pyproject.toml" && "${research_root}" != "/" ]]; do
  research_root="$(dirname "${research_root}")"
done
if [[ ! -f "${research_root}/pyproject.toml" ]]; then
  echo "Could not find the Telemetry Research project root; set ETR_PROJECT_ROOT" >&2
  exit 1
fi

cd "${research_root}"
research_env_args=()
if [[ -f "${research_root}/.emerging-telemetry-research/config.env" ]]; then
  research_env_args+=(--env-file "${research_root}/.emerging-telemetry-research/config.env")
fi
if [[ -f "${research_config_root}/research.env" ]]; then
  research_env_args+=(--env-file "${research_config_root}/research.env")
fi
exec uv run emerging-telemetry-research "${research_env_args[@]}" portable run --json "$@"
