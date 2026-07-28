# Delivery Manifest

This package contains the security-first OpenClaw Emerging Threat Radar implementation. The
approved local deployment performs live Brave and X discovery, authoritative corroboration, and
DB/private-website publication with no routine Discord delivery; unapproved source classes remain
fail-closed.

## Primary handoff documents

- `OPENCLAW_BUILD_PROMPT.md` — direct build brief for OpenClaw/Codex.
- `IMPLEMENTATION_PLAN.md` — detailed implementation, architecture, phases, controls, and acceptance criteria.
- `ARCHITECTURE.md` — system boundaries, components, data flow, and deployment topology.
- `SECURITY.md` and `THREAT_MODEL.md` — prompt-injection resilience, capability security, trust boundaries, and abuse cases.
- `EVALS.md` — discovery-quality, novelty, safety, reliability, and cost evaluation framework.
- `RUNBOOK.md` — operational procedures, incidents, retries, degradation, and recovery.
- `IMPLEMENTATION_BACKLOG.md` — epics, stories, priorities, and definitions of done.

## Visual documentation

- `docs/index.html` — self-contained visual architecture and implementation guide.
- `docs/sample-daily-brief.html` — rich sample threat intelligence report.

## Build assets

- `openclaw/` — example OpenClaw configuration, role definitions, and Lobster workflows.
- `schemas/` — JSON Schemas for evidence, findings, assessments, and reports.
- `policies/` — tool, egress, and untrusted-content gateway policies.
- `config/` — source, model, local-embedding, scoring, schedule, and report configuration.
- `apps/` and `packages/` — internal API, worker CLI, pipeline, connectors, security gateway,
  scoring, verification, delivery planning, telemetry, and storage adapters.
- `infra/` — local observability and service topology.
- `.github/` — CI, CodeQL, Dependabot, security, and ownership controls.

## Validation

Run:

```bash
uv run python scripts/validate_repo.py
uv run pytest
uv run python scripts/run_acceptance.py --output /tmp/radar-acceptance
uv run python scripts/verify_restore.py --output /tmp/radar-restore
```

Before applying the example OpenClaw configuration, validate every field against the installed version:

```bash
openclaw config schema
```
