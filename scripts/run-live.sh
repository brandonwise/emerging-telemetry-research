#!/usr/bin/env bash
set -euo pipefail

radar_repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
radar_keychain_helper="${HOME}/.openclaw/bin/keychain-secret.sh"

if [[ ! -x "${radar_keychain_helper}" ]]; then
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
export DOCKER_CONFIG="${radar_repo_root}/infra/docker-config"
export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock"

export BRAVE_API_KEY
BRAVE_API_KEY="$("${radar_keychain_helper}" BRAVE_API_KEY)"
export XAI_API_KEY
XAI_API_KEY="$("${radar_keychain_helper}" XAI_API_KEY)"
export POSTGRES_PASSWORD
POSTGRES_PASSWORD="$("${radar_keychain_helper}" RADAR_POSTGRES_PASSWORD)"
export MINIO_ROOT_USER
MINIO_ROOT_USER="$("${radar_keychain_helper}" RADAR_MINIO_ROOT_USER)"
export MINIO_ROOT_PASSWORD
MINIO_ROOT_PASSWORD="$("${radar_keychain_helper}" RADAR_MINIO_ROOT_PASSWORD)"

if ! docker info >/dev/null 2>&1; then
  colima start --cpu 2 --memory 4 --disk 20 >&2
fi

docker compose \
  -f "${radar_repo_root}/infra/docker-compose.yml" \
  up -d postgres minio >&2

for radar_attempt in $(seq 1 30); do
  if docker compose \
    -f "${radar_repo_root}/infra/docker-compose.yml" \
    exec -T postgres pg_isready -U radar -d radar >/dev/null 2>&1; then
    break
  fi
  if [[ "${radar_attempt}" -eq 30 ]]; then
    echo "Threat Radar PostgreSQL did not become ready" >&2
    exit 1
  fi
  sleep 1
done

export RADAR_POSTGRES_HOST_PORT="${RADAR_POSTGRES_HOST_PORT:-55432}"
export RADAR_MINIO_HOST_PORT="${RADAR_MINIO_HOST_PORT:-19000}"
export RADAR_MINIO_CONSOLE_HOST_PORT="${RADAR_MINIO_CONSOLE_HOST_PORT:-19001}"
export RADAR_DATABASE_URL="postgresql://radar:${POSTGRES_PASSWORD}@127.0.0.1:${RADAR_POSTGRES_HOST_PORT}/radar"
export RADAR_S3_ENDPOINT_URL="http://127.0.0.1:${RADAR_MINIO_HOST_PORT}"
export RADAR_S3_ACCESS_KEY_ID="${MINIO_ROOT_USER}"
export RADAR_S3_SECRET_ACCESS_KEY="${MINIO_ROOT_PASSWORD}"
export RADAR_S3_BUCKET="threat-radar-raw"
export RADAR_S3_REGION="us-east-1"
export RADAR_S3_SERVER_SIDE_ENCRYPTION="none"

cd "${radar_repo_root}"
exec uv run threat-radar live run \
  --output "${radar_repo_root}/reports/generated" \
  --channel-id "1476897068885872814" \
  --edition "morning" \
  --json
