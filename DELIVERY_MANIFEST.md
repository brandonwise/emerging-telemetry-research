# Delivery Manifest

This package is a production-oriented implementation scaffold for the OpenClaw Emerging Threat Radar.

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
- `config/` — source, model, scoring, schedule, and report configuration.
- `apps/` and `packages/` — starter Python implementation.
- `infra/` — local observability and service topology.
- `.github/` — CI, CodeQL, Dependabot, security, and ownership controls.

## Validation

Run:

```bash
python scripts/validate_repo.py
pytest -q
```

Before applying the example OpenClaw configuration, validate every field against the installed version:

```bash
openclaw config schema
```
