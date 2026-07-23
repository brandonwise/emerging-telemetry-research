# OpenClaw Emerging Threat Radar

A production-oriented implementation blueprint and starter repository for a proactive cyber-threat early-warning capability built on OpenClaw.

The system is designed to discover weak, early signals of high-impact vulnerabilities, exploitation, supply-chain compromise, malicious packages, and related security events **before they become broadly reported**, while remaining evidence-backed, prompt-injection resilient, auditable, reliable, and cost controlled.

## What this repository contains

- A detailed architecture and implementation plan
- A direct build brief for an OpenClaw/Codex coordinator
- A deterministic multi-agent workflow design
- Source, model, scoring, policy, and schedule configuration
- Strict JSON contracts for evidence and findings
- Prompt-injection and content-security controls
- Evaluation, red-team, reliability, and operations plans
- A self-contained visual HTML architecture guide
- A sample rich daily intelligence brief
- Starter Python packages and CI/security scaffolding

## Start here

1. Open `docs/index.html` for the visual system guide.
2. Read `OPENCLAW_BUILD_PROMPT.md` and provide it to the build coordinator.
3. Review `IMPLEMENTATION_PLAN.md`, `SECURITY.md`, `THREAT_MODEL.md`, and `EVALS.md`.
4. Copy `.env.example` to `.env`; never commit the result.
5. Validate the scaffold with `make validate`.
6. Create a private repository with `scripts/create-private-repo.sh <github-org>`.

## System objective

Produce three classes of output:

- **Flash alert:** high-confidence, high-impact emerging event requiring immediate review
- **Watch update:** promising but incomplete signal that should be rechecked frequently
- **Daily intelligence brief:** ranked, evidence-backed findings, changes, source health, and cost telemetry

The system must prefer **no alert** over an ungrounded alert. Every factual claim that reaches a user-facing report must resolve to stored evidence, a retrieval timestamp, and a source URI.

## Core architectural rule

> Untrusted content is data, never instructions.

Raw internet content never reaches the high-privilege coordinator. Collection, sanitization, extraction, correlation, analysis, and publishing are separated by typed contracts and least-privilege tool boundaries.

## High-level flow

```text
DETECT → INGEST → QUARANTINE → SANITIZE → EXTRACT → CORRELATE
       → SCORE → CHALLENGE → VERIFY → PUBLISH → LEARN
```

## Recommended initial stack

- OpenClaw Gateway, agents, cron, Task Flow, and Lobster workflows
- Python 3.12 services and workers
- PostgreSQL 16 with pgvector
- S3-compatible immutable evidence storage
- Optional OpenTelemetry, Prometheus, and Grafana
- Discord embeds plus attached self-contained HTML reports
- Email and PDF adapters after Discord is stable

## Production invariants

1. No agent executes code obtained from monitored sources.
2. No collector can send a Discord message, email, or modify schedules.
3. No publisher can browse the internet.
4. The coordinator receives only sanitized, schema-valid evidence packets.
5. Every state-changing action is deterministic, policy checked, logged, and idempotent.
6. Model output is never trusted until schema validation and deterministic checks pass.
7. Source independence is measured; reposts do not count as corroboration.
8. Confidence, impact, novelty, and organizational relevance are separate concepts.
9. Costs and token usage are attributable by run, stage, model, source, and finding.
10. A report may explicitly state that no material emerging threats were found.

## Repository status

This is an architecture-grade starter scaffold, not a finished threat-intelligence product. Connector credentials, organization-specific asset relevance, source terms, data-retention decisions, and deployment controls must be configured before production use.
