# OpenClaw Emerging Threat Radar

A security-first, evidence-backed cyber-threat early-warning system for OpenClaw.

The approved local production path uses Brave Search API and xAI server-side X Search for bounded
discovery, then corroborates candidates with CISA KEV, CVE List V5, NVD, FIRST EPSS, OSV, and
GitHub Global Security Advisories. It captures authoritative evidence in PostgreSQL and an
object-locked, versioned S3-compatible store; sanitizes hostile content; normalizes entities; builds
source lineage; scores deterministically; produces verified report JSON and self-contained HTML;
and delivers through a fixed-destination, idempotent OpenClaw tool.

The daily OpenClaw job runs at 7:30 AM America/New_York. Browser automation is not part of source
collection; it is used only for report-rendering QA.

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

Run the approved live pipeline locally:

```bash
scripts/run-live.sh
```

The script loads Brave, xAI, PostgreSQL, and MinIO credentials from macOS Keychain, verifies
FileVault, starts the loopback-only data services when needed, applies immutable migrations and
bucket retention, and emits one delivery-ready JSON object. It does not send Discord messages
directly; delivery remains isolated behind `radar_delivery_send`.

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

## Grounded self-improvement

The daily production graph is wrapped by a separate weekly champion/challenger loop. It reads
immutable reports and append-only analyst feedback, evaluates the current daily publication
threshold and bounded challengers in parallel, runs the frozen acceptance anchors, and either stops
or emits a proposal requiring a resumable Lobster approval.

It cannot change Flash or Watch thresholds, confirmation rules, source terms, content security,
egress, or the fixed Discord destination. It never publishes a report. Approved changes are
hash-checked, limited to one five-point daily-threshold step, and ship with an immutable rollback
snapshot and receipt.

Record one analyst label:

```bash
uv run threat-radar feedback record \
  reports/generated/<run-id>/<report-id>.json \
  <finding-id> \
  actionable_and_early \
  --submitted-by operator \
  --json
```

Run one proposal-only cycle:

```bash
uv run threat-radar improve analyze \
  --reports reports/generated \
  --feedback reports/feedback \
  --output reports/generated/improvement \
  --json
```

Run the reviewed workflow through the OpenClaw Lobster tool with this payload:

```json
{
  "action": "run",
  "pipeline": "openclaw/workflows/self-improvement.lobster",
  "cwd": "workspace/openclaw-emerging-threat-radar"
}
```

The workflow currently stops with `insufficient_evidence` until at least 20 grounded labels,
including positive and negative outcomes, exist. The weekly schedule is intentionally disabled
until that feedback corpus is real.

## Production boundary

Read [BLOCKERS.md](BLOCKERS.md) and [THREAT_MODEL_APPROVAL.md](THREAT_MODEL_APPROVAL.md). Approval is
limited to this local OpenClaw instance, the explicitly enabled sources, and the private fixed
Discord destination. Browser collection, arbitrary web execution, authenticated vendor portals,
malware detonation, organization inventory, and autonomous defensive action remain out of scope.

Disabled source classes stay fail-closed until their terms, credentials, and threat-model changes
receive separate approval.

## Documentation

- `docs/index.html` — visual architecture and implementation guide
- `docs/sample-daily-brief.html` — report design sample
- `reports/samples/frozen-flash/` — generated report, immutable inputs, and audit log
- `docs/MILESTONE_ACCEPTANCE.md` — design notes, acceptance evidence, and remaining gates
- `ARCHITECTURE.md`, `SECURITY.md`, `THREAT_MODEL.md`, `EVALS.md` — controlling specifications
- `RUNBOOK.md` — operations, incident, replay, restore, and rollback procedures
- `openapi/openapi.yaml` — versioned internal service contract
- `docs/adr/` — architecture decisions and security deviations
- `docs/adr/0008-grounded-self-improvement-graph.md` — loop, graph, approval, and rollback design
