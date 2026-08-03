# Production readiness runbook

Emerging Telemetry Research ships fail closed. A clone can validate contracts and run fixtures immediately, but
it cannot collect, schedule, deliver externally, or apply self-improvement proposals until a local
operator approval authorizes those exact capabilities against an unchanged control hash.

`1.1.0rc1` is a release candidate, not a GA declaration. Promote it to `1.1.0` only after the
target-environment harness canary, backup/restore, alert, chaos, rollback, and signed private
release evidence in this runbook are complete.

## Supported deployment targets

- Python 3.12–3.14 on Linux, macOS, and Windows
- Portable SQLite plus content-addressed local objects
- PostgreSQL plus versioned, object-locked S3-compatible storage
- OCI container for the internal API behind a trusted mTLS-terminating proxy
- OpenClaw, Codex, Claude Code, OpenAI-compatible APIs, or an allowlisted provider plugin

CI tests the three Python versions on Ubuntu, macOS, and Windows. The complete PostgreSQL,
acceptance, replay, restore, security, container, and packaging gates run on Linux.

## Promotion checklist

1. Create the private local workspace with `emerging-telemetry-research onboard` or `setup init`.
2. Put secrets in an OS keyring, deployment secret file, or managed environment; commit only
   `env://`, `keyring://`, or `file://` references.
3. Review local discovery, source, source-terms, scoring, model, and embedding configuration.
4. Run fixture missions, `make check`, and `make package-smoke`.
5. Generate an approval request and independently review its source list, capabilities, terms,
   and control hash.
6. Apply the approval with a named operator, ticket/change ID, and short expiration.
7. Run `setup doctor` for the intended profile and certify the selected real harness with
   `setup harness-test --acknowledge-cost`.
8. Start in agent `plan`, then `shadow`; promote to `active` only after reviewing stored evals and
   the harness receipt.
9. Keep external delivery disabled until destination, recipient, and credential boundaries have
   their own review.
10. Protect `main`, require CI/Security/CodeQL and CODEOWNERS review, and retain private releases.

## Secret references

Use one of these forms in `.emerging-telemetry-research/config.env`:

```dotenv
BRAVE_API_KEY_REF=keyring://emerging-telemetry-research/BRAVE_API_KEY
XAI_API_KEY_REF=env://DEPLOYMENT_XAI_API_KEY
ETR_DATABASE_URL_REF=file:///run/secrets/research_database_url
```

File secrets must be absolute, regular, UTF-8 files no larger than 64 KiB. On POSIX they must be
owned by the process user and have no group/world permissions. Symlinks are rejected. The setup
and doctor commands report only source and readiness metadata, never values.

## Deploy and operate

Portable runs use `.emerging-telemetry-research/config.env` explicitly:

```bash
uv run emerging-telemetry-research --env-file .emerging-telemetry-research/config.env \
  portable run --output reports/generated --json
```

Production runs additionally require PostgreSQL and object-store references:

```bash
uv run emerging-telemetry-research --env-file .emerging-telemetry-research/config.env \
  live run --output reports/generated --json
```

The hardened API container profile is loopback-only, read-only, non-root, capability-free, and
receives its database URL through a Compose secret:

```bash
export ETR_API_DATABASE_URL='postgresql://research:...@postgres:5432/research'
docker compose -f infra/docker-compose.yml --profile application up -d research-api
```

Do not expose the internal API directly. Put it behind a proxy that validates client certificates,
strips inbound identity headers, and injects the verified certificate SHA-256 only from a trusted
proxy IP. `/healthz` reveals process liveness only, `/readyz` reveals only repository readiness,
and `/v1/health` remains authenticated.

Monitor source degradation, workflow failures/retries, parser isolation failures, injection
events, model/provider latency and token use, estimated cost, delivery receipts, and approval
expiration. Alert before an approval expires and fail the scheduled run if `setup doctor` is not
ready.

Use `schedule serve` for a vendor-neutral long-running worker, or invoke `schedule run-due` from an
existing service manager. The durable database prevents duplicate concurrent claims and recovers
an abandoned lease. Back up `.emerging-telemetry-research/schedules.db` with other SQLite state.

## Backup, restore, and rollback

- SQLite: stop writers, snapshot the database plus `state/objects` and reports together.
- PostgreSQL: use a consistent database backup and retain migration hashes.
- S3-compatible objects: retain versioning, Object Lock, encryption, and lifecycle policy.
- Never rewrite immutable evidence or reports; publish a corrected version with lineage.
- Verify restores with `make restore-test` before promotion and on a scheduled cadence.
- Stop model calls immediately with `ETR_AGENT_MODE=plan`.
- Roll back an activated mission with its hash-bound activation receipt.
- Revoke a deployment capability by removing the local approval or allowing it to expire.

## Release and recovery

Tags matching `v*` run release validation, tests, a clean wheel install, fixture execution,
CycloneDX SBOM generation, and SHA-256 generation before creating a private GitHub release. Roll
back by deploying the prior immutable tag and wheel; do not mutate an existing tag or release
artifact.

For a suspected compromise: disable the affected source/provider, revoke its credential, preserve
evidence and audit records, stop publication/delivery, identify derived outputs, rotate secrets,
and add the failure mode to the regression suite before reactivation.
