#!/usr/bin/env bash
set -euo pipefail

research_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
research_keychain_helper="${HOME}/.openclaw/bin/keychain-secret.sh"
research_edition="${LOBSTER_ARG_EDITION:-morning}"

if [[ ! -x "${research_keychain_helper}" ]]; then
  echo "OpenClaw Keychain helper is unavailable" >&2
  exit 1
fi

# Local MinIO does not have a KMS service. Its volume is protected by the
# encrypted host disk; refuse to run if that protection is unavailable.
if [[ "$(fdesetup status)" != "FileVault is On." ]]; then
  echo "FileVault must be enabled for local MinIO evidence storage" >&2
  exit 1
fi

# Colima must not inherit Docker Desktop's credential helper. On hosts where
# Docker Desktop is unavailable, docker-credential-desktop can block forever.
export DOCKER_CONFIG="${research_repo_root}/infra/docker-config"
export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock"

export BRAVE_API_KEY
BRAVE_API_KEY="$("${research_keychain_helper}" BRAVE_API_KEY)"
export XAI_API_KEY
XAI_API_KEY="$("${research_keychain_helper}" XAI_API_KEY)"
export POSTGRES_PASSWORD
POSTGRES_PASSWORD="$("${research_keychain_helper}" ETR_POSTGRES_PASSWORD)"
export MINIO_ROOT_USER
MINIO_ROOT_USER="$("${research_keychain_helper}" ETR_MINIO_ROOT_USER)"
export MINIO_ROOT_PASSWORD
MINIO_ROOT_PASSWORD="$("${research_keychain_helper}" ETR_MINIO_ROOT_PASSWORD)"

if ! docker info >/dev/null 2>&1; then
  colima start --cpu 2 --memory 4 --disk 20 >&2
fi

docker compose \
  -f "${research_repo_root}/infra/docker-compose.yml" \
  up -d postgres minio >&2

for research_attempt in $(seq 1 30); do
  if docker compose \
    -f "${research_repo_root}/infra/docker-compose.yml" \
    exec -T postgres pg_isready -U research -d research >/dev/null 2>&1; then
    break
  fi
  if [[ "${research_attempt}" -eq 30 ]]; then
    echo "Telemetry Research PostgreSQL did not become ready" >&2
    exit 1
  fi
  sleep 1
done

export ETR_POSTGRES_HOST_PORT="${ETR_POSTGRES_HOST_PORT:-55432}"
export ETR_MINIO_HOST_PORT="${ETR_MINIO_HOST_PORT:-19000}"
export ETR_MINIO_CONSOLE_HOST_PORT="${ETR_MINIO_CONSOLE_HOST_PORT:-19001}"
export ETR_DATABASE_URL="postgresql://research:${POSTGRES_PASSWORD}@127.0.0.1:${ETR_POSTGRES_HOST_PORT}/research"
export ETR_S3_ENDPOINT_URL="http://127.0.0.1:${ETR_MINIO_HOST_PORT}"
export ETR_S3_ACCESS_KEY_ID="${MINIO_ROOT_USER}"
export ETR_S3_SECRET_ACCESS_KEY="${MINIO_ROOT_PASSWORD}"
export ETR_S3_BUCKET="telemetry-research-raw"
export ETR_S3_REGION="us-east-1"
export ETR_S3_SERVER_SIDE_ENCRYPTION="none"
export ETR_AGENT_MODE="${ETR_AGENT_MODE:-shadow}"
export ETR_AGENT_ADAPTER="${ETR_AGENT_ADAPTER:-openclaw}"
export ETR_AGENT_TIMEOUT_SECONDS="${ETR_AGENT_TIMEOUT_SECONDS:-300}"

cd "${research_repo_root}"
exec uv run emerging-telemetry-research live run \
  --output "${research_repo_root}/reports/generated" \
  --edition "${research_edition}" \
  --json
