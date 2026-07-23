# Implementation Backlog

## P0 — Foundation and safety boundary

- [ ] Create private GitHub repository and configure protected `main`
- [ ] Replace placeholder CODEOWNERS teams
- [ ] Pin every GitHub Action to a reviewed commit SHA
- [ ] Run `openclaw config schema` and adapt `openclaw.example.json5`
- [ ] Create ADRs for database, queue, object storage, egress, retention, and model providers
- [ ] Implement secret-store integration and per-role identities
- [ ] Implement strict OpenAPI contract and generated clients
- [ ] Create PostgreSQL migrations and immutable artifact records
- [ ] Implement centralized safe-fetch gateway and SSRF tests
- [ ] Implement raw object store and content hashing
- [ ] Implement run/step state machine and idempotency
- [ ] Implement source registry, cursor, health, terms, and retention records

## P0 — Content security

- [ ] Isolated parser workers with CPU/memory/time/file limits
- [ ] HTML active-content and hidden-text removal
- [ ] Unicode and encoding canonicalization
- [ ] Archive depth/ratio/member controls
- [ ] PDF/document/image safe extraction strategy
- [ ] Malware scanning and YARA integration
- [ ] Prompt-injection risk classifier and security event records
- [ ] Bounded evidence excerpt creation
- [ ] Cross-agent JSON Schema validation and unknown-field rejection
- [ ] No raw content route to analytical agents

## P0 — First vertical slice

- [ ] CISA KEV connector
- [ ] CVE List V5 connector
- [ ] NVD connector
- [ ] EPSS enrichment
- [ ] OSV connector
- [ ] GitHub Advisory connector
- [ ] CVE/package/entity normalization
- [ ] Evidence ledger and source-lineage graph
- [ ] Deterministic scoring
- [ ] Specialist, skeptic, verifier, and chief coordinator execution
- [ ] Report JSON, HTML renderer, Discord delivery
- [ ] Usage and estimated cost attribution
- [ ] Replay test from frozen artifacts

## P1 — Emerging precursor coverage

- [ ] GitHub commit/issue/release precursor adapter
- [ ] Package registry event adapters
- [ ] Maintainer and ownership change detection
- [ ] Install-script and provenance regression rules
- [ ] Typosquat/homoglyph detection
- [ ] Certificate transparency and suspicious domain adapter
- [ ] Vendor CSAF 2.1/VEX feed directory
- [ ] Brave freshness query planner
- [ ] Curated X researcher adapter
- [ ] Curated Reddit adapter
- [ ] Media-baseline and lead-time calculation

## P1 — Analytics and quality

- [ ] 15m/1h/6h/24h/7d feature windows
- [ ] EWMA and CUSUM burst features
- [ ] Independent-source classification
- [ ] Historical source reliability calibration
- [ ] Organization relevance plug-in and demo inventory
- [ ] Confidence calibration
- [ ] Correction/downgrade workflow
- [ ] Analyst feedback UI/API

## P1 — Reliability and operations

- [ ] Task Flow integration and gateway-restart recovery
- [ ] Dead-letter queue and replay tooling
- [ ] Model/provider and source circuit breakers
- [ ] Partial-report behavior
- [ ] Delivery idempotency and receipts
- [ ] Backup/restore automation and test
- [ ] OpenTelemetry metrics, traces, and redacted logs
- [ ] SLO dashboards and operator alerts
- [ ] Incident runbooks exercised

## P1 — Evaluation and launch

- [ ] Historical event corpus
- [ ] Benign anomaly corpus
- [ ] Injection corpus across all parsers
- [ ] Chaos/failure test suite
- [ ] Precision, lead-time, calibration, cost, and citation dashboards
- [ ] Shadow mode
- [ ] Human release review
- [ ] OpenClaw deep security audit
- [ ] Production readiness review

## P2 — Expansion

- [ ] Asset/SBOM/dependency inventory integrations
- [ ] STIX 2.1 and MISP export
- [ ] Email and PDF delivery
- [ ] Operator dashboard
- [ ] Optional isolated lawful non-indexed-source collector
- [ ] Dedicated malware lab under a separate threat model
- [ ] Multi-tenant policy and data separation, if required
