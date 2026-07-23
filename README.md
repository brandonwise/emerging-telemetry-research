# OpenClaw Emerging Threat Radar

A security-first, evidence-backed cyber-threat early-warning system for OpenClaw.

The implemented shadow-mode vertical slice ingests frozen CISA KEV, CVE List V5, NVD, EPSS,
OSV, and GitHub Advisory fixtures; captures immutable evidence; sanitizes hostile content;
normalizes CVE/package entities; builds source lineage; scores deterministically; runs bounded
specialist, skeptic, citation-verifier, and coordinator reviews; and produces verified report JSON,
Discord delivery plans, self-contained HTML, usage records, and a hash-chained audit log.

Live collection, schedules, and external delivery are deliberately disabled. They cannot be enabled
until the threat model, source terms, deployment, and production-readiness gates are approved.

## Run it

Requires Python 3.12 and `uv`.

```bash
uv sync --extra dev --python 3.12
uv run python scripts/validate_repo.py
uv run pytest
uv run python scripts/run_acceptance.py --output /tmp/radar-acceptance
uv run python scripts/verify_restore.py --output /tmp/radar-restore
```

Generate one complete fixture report:

```bash
uv run threat-radar fixture run \
  tests/fixtures/vertical_slice/flash-manifest.json \
  --output /tmp/radar-flash \
  --json
```

The internal API is available with:

```bash
uv run uvicorn apps.api.main:app --host 127.0.0.1 --port 8080
```

It fails closed unless PostgreSQL, a trusted mTLS proxy IP, and a certificate-fingerprint-to-role
map are configured. The proxy must terminate and verify mutual TLS, strip inbound identity headers,
and inject `X-Client-Cert-SHA256`; callers cannot self-assert that header over an exposed route.

## What is enforced

- External content is data, never instructions.
- Raw source content cannot reach the chief coordinator.
- Collectors cannot send messages, access schedules, or receive delivery credentials.
- Publishers cannot browse and can send only through a fixed-destination OpenClaw tool.
- Cross-agent/model payloads reject unknown fields and non-JSON wrappers.
- Report claims require stored evidence IDs and deterministic verification.
- Reposts and syndication collapse into one originating source chain.
- Fetching enforces HTTPS allowlists, global-address checks, redirect/DNS revalidation, rate limits,
  MIME and size limits, sensitive-header stripping, timeouts, and content hashing.
- Content processing strips active/hidden markup, detects visible/encoded/delayed injection,
  constrains archives, exposes a malware-scanner hook, and gates model access by risk.
- PostgreSQL work claiming uses `SKIP LOCKED`; API commands and delivery plans are idempotent.
- Raw, sanitized, evidence, report, policy, and security records are append-only where required.
- CI actions and service images are version pinned; CI runs schema, lint, type, test, PostgreSQL,
  replay, security, and frozen acceptance gates.
- OpenTelemetry exposes bounded, content-free workflow/source/model/delivery/security metrics.

## Architecture

```text
approved source plan
  → centralized safe fetch
  → immutable quarantine
  → content-security gateway
  → schema-bound observations
  → entity + source-lineage graph
  → deterministic scoring
  → specialist → skeptic → citation verifier → coordinator
  → verified report JSON
  → deterministic HTML + fixed-destination Discord plan
```

OpenClaw cron and reviewed Lobster workflows own orchestration. PostgreSQL owns durable state.
Conversation history owns neither.

## Release boundaries

Read [BLOCKERS.md](BLOCKERS.md) and [THREAT_MODEL_APPROVAL.md](THREAT_MODEL_APPROVAL.md). Until those
records are resolved:

- every source in `config/sources.yaml` remains disabled;
- `config/schedules.yaml` remains globally disabled;
- Discord and all external delivery remain disabled;
- the live Lobster workflow exits through a blocking approval gate;
- only frozen-fixture and shadow evaluation paths are runnable.

The private GitHub repository, branch protection, browser-rendered UI review, live source
authorization, and Discord destination are operator actions and are intentionally not performed by
the local build.

## Documentation

- `docs/index.html` — visual architecture and implementation guide
- `docs/sample-daily-brief.html` — report design sample
- `reports/samples/frozen-flash/` — generated report, immutable inputs, and audit log
- `docs/MILESTONE_ACCEPTANCE.md` — design notes, acceptance evidence, and remaining gates
- `ARCHITECTURE.md`, `SECURITY.md`, `THREAT_MODEL.md`, `EVALS.md` — controlling specifications
- `RUNBOOK.md` — operations, incident, replay, restore, and rollback procedures
- `openapi/openapi.yaml` — versioned internal service contract
- `docs/adr/` — architecture decisions and security deviations
