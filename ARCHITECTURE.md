# Architecture Specification

## Components

| Component | Purpose | Trust level |
|---|---|---|
| OpenClaw Gateway | Agent routing, scheduling, channel integration, tool policy | Privileged control plane |
| Scheduler | Durable triggers and run identity | Privileged control plane |
| Workflow Engine | Typed deterministic stage transitions | Privileged control plane |
| Connector Workers | Source-specific collection | Internet-facing, untrusted |
| Fetch/Egress Gateway | SSRF, redirect, MIME, size, and destination policy | Security boundary |
| Raw Object Store | Immutable source bytes and metadata | Quarantine |
| Content Security Gateway | Sanitization, extraction safety, injection risk | Security boundary |
| Normalizer | Canonical entities and claims | Trusted code |
| Correlator | Cluster and source-dependency graph | Trusted code |
| Scoring Engine | Deterministic features and thresholds | Trusted code |
| Model Router | Select model, budget, context, and retries | Privileged control plane |
| Analyst Agents | Bounded reasoning over sanitized packets | Medium trust |
| Verifier | Claim/evidence and policy checks | High scrutiny |
| Report Renderer | Deterministic HTML/embed/email output | Publishing zone |
| Delivery Adapter | Discord/email/file delivery | Narrow privileged credential |
| Telemetry Pipeline | Metrics, traces, logs, usage/cost | Trusted operations |

## Logical diagram

```text
┌──────────────────────────── HOSTILE INTERNET ────────────────────────────┐
│ Tier 0 feeds │ code/packages │ social/research │ vendor │ media baseline │
└──────────────────────────────────┬────────────────────────────────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │ Connector + Fetch Gateway   │
                    │ allowlist • SSRF • budgets  │
                    └──────────────┬──────────────┘
                                   │ immutable artifact reference
                    ┌──────────────▼──────────────┐
                    │ Quarantine Object Store     │
                    └──────────────┬──────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │ Content Security Gateway    │
                    │ sanitize • scan • classify  │
                    └──────────────┬──────────────┘
                                   │ schema-valid observations
              ┌────────────────────▼────────────────────┐
              │ PostgreSQL Evidence / Entity / Run DB   │
              └─────────┬────────────────────┬───────────┘
                        │                    │
             ┌──────────▼──────────┐  ┌─────▼─────────────────┐
             │ Correlate + Score   │  │ Usage + Source Health │
             └──────────┬──────────┘  └───────────────────────┘
                        │ promoted clusters only
             ┌──────────▼──────────────────────────────────────┐
             │ Specialist → Skeptic → Verifier → Coordinator  │
             │ typed evidence packets; no raw web content      │
             └──────────┬──────────────────────────────────────┘
                        │ validated report JSON
             ┌──────────▼──────────┐
             │ Deterministic Render │
             └──────┬───────┬──────┘
                    │       │
                 Discord   HTML/email/download
```

## Deployment topology

### Minimum viable production

- One OpenClaw Gateway instance
- Two or more worker processes
- PostgreSQL with automated backup
- S3-compatible object store with versioning
- Reverse proxy and outbound egress policy
- OpenTelemetry collector
- Discord destination

### Scale-out

- Separate worker pools by source class and trust zone
- Independent sanitizer pool
- Read replicas for analytics/reporting
- Object-store lifecycle policies
- Queue partitions by source and priority
- Multiple publisher instances with idempotent delivery

## Data model

### Core tables

- `runs`
- `workflow_steps`
- `source_registry`
- `source_cursors`
- `source_health`
- `raw_artifacts`
- `sanitized_artifacts`
- `observations`
- `entities`
- `entity_aliases`
- `relationships`
- `evidence_items`
- `clusters`
- `cluster_members`
- `features`
- `assessments`
- `assessment_claims`
- `claim_evidence`
- `reports`
- `deliveries`
- `analyst_feedback`
- `model_usage`
- `policy_decisions`
- `security_events`

### Required version fields

Every derived object records:

- Input artifact/evidence hashes
- Schema version
- Code revision
- Prompt/template revision
- Model provider and model ID
- Model parameters and reasoning tier
- Policy bundle revision
- Created timestamp and actor

## APIs

Use strict OpenAPI contracts and fail closed on undeclared routes, parameters, or fields.

Suggested internal routes:

```text
POST /v1/runs
POST /v1/artifacts
POST /v1/sanitization-jobs
POST /v1/observations
POST /v1/clusters/recompute
POST /v1/assessments
POST /v1/reports/render
POST /v1/deliveries
GET  /v1/evidence/{id}
GET  /v1/clusters/{id}/packet
GET  /v1/runs/{id}/usage
GET  /v1/source-health
```

Agents receive narrow capability wrappers rather than the general API client.

## Queue strategy

For the first release, PostgreSQL can provide durable work claiming with `FOR UPDATE SKIP LOCKED`, reducing infrastructure. Move to a dedicated broker only when throughput or isolation demands it.

A queue item includes:

- Work type
- Run and step IDs
- Priority
- Input reference IDs
- Idempotency key
- Attempt count
- Not-before timestamp
- Deadline
- Policy context

## State ownership

- The database owns run and workflow state.
- The object store owns raw evidence bytes.
- OpenClaw session history is disposable execution context.
- Agent memory must not be used as the source of truth.
- Reports are immutable versions; corrections create a new version and link to the prior one.
