# Implementation Backlog

## P0 — Foundation and safety boundary

- [ ] Create private GitHub repository and configure protected `main`
- [x] Replace placeholder CODEOWNERS teams
- [x] Pin every GitHub Action to a reviewed commit SHA
- [x] Run `openclaw config schema` and adapt `openclaw.example.json5`
- [x] Create ADRs for database, queue, object storage, egress, retention, and model providers
- [x] Implement macOS Keychain secret integration for the local production runner
- [ ] Implement portable per-role workload identities for non-local deployments
- [x] Implement strict OpenAPI contract
- [ ] Generate language-specific clients when a deployment consumer requires them
- [x] Create PostgreSQL migrations and immutable artifact records
- [x] Implement centralized safe-fetch gateway and SSRF tests
- [x] Implement raw object store and content hashing
- [x] Implement run/step state machine and idempotency
- [x] Implement source registry, cursor, health, terms, and retention records

## P0 — Content security

- [ ] Isolated parser workers with CPU/memory/time/file limits
- [x] HTML active-content and hidden-text removal
- [x] Unicode and encoding canonicalization
- [x] Archive depth/ratio/member controls
- [ ] PDF/document/image safe extraction strategy
- [ ] Malware scanning and YARA integration
- [x] Prompt-injection risk classifier and security event records
- [x] Bounded evidence excerpt creation
- [x] Cross-agent JSON Schema validation and unknown-field rejection
- [x] No raw content route to analytical agents

## P0 — First vertical slice

- [x] CISA KEV connector
- [x] CVE List V5 connector
- [x] NVD connector
- [x] EPSS enrichment
- [x] OSV connector
- [x] GitHub Advisory connector
- [x] CVE/package/entity normalization
- [x] Evidence ledger and source-lineage graph
- [x] Deterministic scoring
- [x] Bounded specialist, skeptic, verifier, and chief shadow chain
- [x] Report JSON, HTML renderer, and fixed-destination Discord delivery plan
- [x] Usage and estimated cost attribution
- [x] Replay test from frozen artifacts

## P1 — Emerging precursor coverage

- [ ] GitHub commit/issue/release precursor adapter
- [ ] Package registry event adapters
- [ ] Maintainer and ownership change detection
- [ ] Install-script and provenance regression rules
- [ ] Typosquat/homoglyph detection
- [ ] Certificate transparency and suspicious domain adapter
- [ ] Vendor CSAF 2.1/VEX feed directory
- [x] Brave freshness query planner
- [x] Curated X researcher adapter through xAI server-side X Search
- [ ] Curated Reddit adapter
- [x] Media-baseline and lead-time calculation

## P1 — Analytics and quality

- [ ] 15m/1h/6h/24h/7d feature windows
- [ ] EWMA and CUSUM burst features
- [x] Independent-source classification
- [ ] Historical source reliability calibration
- [x] Organization relevance plug-in and demo inventory
- [ ] Confidence calibration
- [ ] Correction/downgrade workflow
- [ ] Analyst feedback UI/API

## P1 — Reliability and operations

- [x] Lobster workflow and isolated OpenClaw cron integration
- [ ] Durable mid-run resume across gateway restarts
- [x] Dead-letter queue and deterministic replay primitive
- [ ] Model/provider and source circuit breakers
- [x] Partial-report behavior
- [x] Delivery idempotency and receipts
- [x] Local immutable-evidence restore test
- [ ] Off-host PostgreSQL PITR and object-store disaster-recovery automation
- [x] OpenTelemetry metrics/traces with bounded content-free attributes
- [x] Prometheus operator alert rules
- [ ] Incident runbooks exercised

## P1 — Evaluation and launch

- [ ] Historical event corpus
- [ ] Benign anomaly corpus
- [ ] Injection corpus across all parsers
- [ ] Chaos/failure test suite
- [ ] Precision, lead-time, calibration, cost, and citation dashboards
- [x] Frozen shadow evaluation path
- [x] Human approval for the bounded local daily brief
- [ ] Accumulate Flash-release shadow metrics
- [ ] Complete off-host production readiness review

## P2 — Expansion

- [ ] Asset/SBOM/dependency inventory integrations
- [ ] STIX 2.1 and MISP export
- [ ] Email and PDF delivery
- [ ] Operator dashboard
- [ ] Optional isolated lawful non-indexed-source collector
- [ ] Dedicated malware lab under a separate threat model
- [ ] Multi-tenant policy and data separation, if required
