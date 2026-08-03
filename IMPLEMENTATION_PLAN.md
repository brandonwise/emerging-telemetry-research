# Detailed Implementation Plan

## 1. Mission and success definition

Build an early-warning intelligence system that identifies material cyber threats while they are still weak, fragmented, or confined to specialist communities. It should not merely summarize widely syndicated news.

A successful implementation will:

- Surface high-impact events earlier than a defined media baseline
- Distinguish observation, inference, and confirmed fact
- Cite every user-facing factual claim
- Withstand hostile content and prompt-injection attempts
- Run reliably on schedules and recover from partial failures
- Provide clear confidence, severity, novelty, momentum, and relevance scores
- Use expensive reasoning only where it materially improves decisions
- Report token, request, latency, and estimated cost by model and workflow stage
- Be straightforward to extend with a new source, model, rule, or delivery channel

### Primary outcome metrics

| Metric | Initial production gate |
|---|---:|
| Citation coverage for factual claims | 100% |
| Citation-to-claim entailment accuracy | ≥ 98% |
| Unauthorized state-changing tool calls in adversarial tests | 0 |
| Unauthorized secret/data exfiltration in adversarial tests | 0 |
| Precision among top five daily findings after shadow tuning | ≥ 80% |
| Scheduled-run success | ≥ 99% |
| Flash-alert detection-to-delivery p95 | < 15 minutes after qualifying evidence arrives |
| Duplicate or syndicated items presented as independent findings | < 2% |
| Cost attributable to run/model/stage | 100% |

Lead time, recall, and false-alert targets should be baselined during shadow mode rather than invented before a representative historical dataset exists.

---

## 2. Architecture mapped to the intelligence platform

### Mesh and Runtime

OpenClaw hosts isolated specialist agents, schedules, tool policies, browser/search access, and deterministic workflow execution. Python workers provide source adapters and content processing. Each worker is separately deployable and horizontally scalable.

### Control Plane

The control plane owns orchestration, source budgets, policies, content-security decisions, model routing, scoring, evaluation gates, approvals, rate limits, and run state. Agents never own durable workflow state.

### Data Plane

The data plane stores immutable raw artifacts, normalized observations, entities, relationships, evidence packets, clusters, assessments, reports, feedback, and usage telemetry. It enables replay and audit without refetching the internet.

### Experience Plane

The experience plane produces Discord embeds, full HTML briefs, email, downloadable files, and later an operator UI. Rendering is deterministic from validated report JSON.

### Telemetry-to-action loop

| Loop stage | Telemetry Research capability |
|---|---|
| Detect | Scheduled source polling, burst detection, anomaly rules, source watches |
| Ingest | Versioned adapters, safe fetch, hashing, immutable capture |
| Store | Evidence object store and normalized relational records |
| Surface | Clusters, timelines, score components, source health |
| Decide | Bounded model analysis, skeptic review, policy thresholds |
| Act | Alert, brief, watchlist update, approved defensive recommendation |
| Verify | Citation verification, delivery receipt, analyst feedback, retrospectives |

---

## 3. Trust zones and hard boundaries

### Zone A — Internet and hostile content

Everything fetched from the internet is hostile until proven otherwise. This includes authoritative sites, code repositories, social media, package metadata, PDFs, images, feeds, comments, and embedded metadata.

### Zone B — Quarantine

Raw bytes are stored with source URI, retrieval timestamp, HTTP metadata, content type, size, hash, and fetch policy. Nothing in this zone is interpreted as an instruction and nothing is executed.

### Zone C — Sanitized evidence

Content passes deterministic decoding, canonicalization, decompression limits, malware scanning, active-content removal, hidden-text detection, prompt-injection classification, and schema-bound extraction. Only normalized observations and bounded excerpts can exit this zone.

### Zone D — Analytical control plane

Correlators, scorers, reviewers, and the coordinator operate only on typed evidence packets. They do not receive raw pages. Their tools are limited to read-only evidence retrieval and structured assessment submission.

### Zone E — Publishing

A renderer receives validated report JSON and static templates. It cannot browse, execute source content, or access collector credentials. Discord/email delivery uses dedicated credentials unavailable to research agents.

---

## 4. Source strategy

The system should use many sources but treat them differently. More sources do not automatically create more confidence.

### Tier 0 — Structured, authoritative facts

Poll frequently and use as direct evidence:

- CISA Known Exploited Vulnerabilities
- CVE List V5 and NVD
- FIRST EPSS
- OSV and ecosystem advisories
- GitHub Global Security Advisories
- OpenSSF malicious-package data
- Vendor PSIRT, CERT, ICS, CSAF 2.1, VEX, and release advisories
- Government and sector-specific alerts

### Tier 1 — Upstream precursors

These often provide the earliest strong signal:

- Security-relevant commits, issue discussions, release tags, emergency hotfixes, and repository advisories
- Package publication, yanking, ownership transfer, maintainer change, dependency graph change, install-script change, obfuscation, and suspicious network behavior
- Proof-of-concept repository creation and rapid fork/star activity, without executing the content
- Certificate-transparency patterns and suspicious domains related to known projects
- Public malware and indicator feeds from approved providers
- Vendor documentation changes and silently altered fixed-version statements

### Tier 2 — Researcher and community observations

Use for discovery and momentum, not confirmation by itself:

- Curated X/Twitter lists and searches
- Reddit communities
- TikTok or short-form technical posts where approved access exists
- Mastodon, Bluesky, mailing lists, specialist blogs, conference material
- Approved public Discord, Matrix, or Telegram communities

Access must follow platform terms, licensing, rate limits, and applicable law. A source may be disabled globally or by tenant.

### Tier 3 — Mainstream and trade media

Use primarily to:

- Establish a media first-publication baseline
- Confirm that a story has become broadly known
- Detect contradictions or corrected facts
- Measure the research's lead time

Media saturation should reduce novelty, not increase it.

### Deep-web boundary

“Deep web” means authorized and lawful OSINT that is not normally indexed, such as vendor portals, public archives, feeds, and approved communities. The initial production system must not perform unauthorized access, credential attacks, interactive criminal-market engagement, or indiscriminate scanning. An optional Tor-based read-only collector, if legally approved, must run in a separate environment with no corporate network route, no downloads, no identities, and no interaction.

---

## 5. Source adapter contract

Every connector implements the same interface:

```python
class SourceAdapter(Protocol):
    source_id: str
    source_class: str
    trust_tier: int

    async def plan(self, cursor: dict | None) -> FetchPlan: ...
    async def fetch(self, request: FetchRequest) -> RawArtifact: ...
    async def checkpoint(self, result: FetchResult) -> dict: ...
    async def health(self) -> SourceHealth: ...
```

Required behavior:

- Conditional requests with ETag and Last-Modified where supported
- Explicit timeout, retry, backoff, and rate-limit handling
- Cursor/checkpoint durability
- Stable canonical URI and content hash
- Idempotency key: `source_id + canonical_uri + content_version`
- Raw artifact size limits and content-type allowlist
- No automatic archive extraction beyond configured depth and size ratio
- Health record for freshness, latency, error rate, and coverage
- Source terms and retention metadata

Connectors publish raw-artifact references to the quarantine queue. They never call a model or create a user-facing alert.

---

## 6. Detection and correlation pipeline

### Stage 0 — Deterministic collection

- Run source plans on independent schedules
- Fetch only changed or newly discovered artifacts
- Hash and deduplicate raw content
- Store immutable artifacts and metadata
- Reject disallowed schemes, destinations, MIME types, and oversized responses

### Stage 1 — Content-security gateway

- Canonicalize encodings and Unicode
- Remove zero-width and bidirectional control characters while preserving a detection record
- Extract text from supported formats in a sandbox
- Strip active HTML, scripts, CSS, forms, iframes, event handlers, SVG scripts, and hidden text
- Enforce archive depth, file count, decompression ratio, memory, CPU, and wall-clock limits
- Scan with ClamAV/YARA or an approved malware service
- Detect instruction-like language, tool-call bait, secret requests, role impersonation, and delayed instructions
- Assign content risk and quarantine disposition

The system stores both the original hash and sanitized representation hash. High-risk content may still contribute narrow indicators after deterministic extraction, but it never reaches a reasoning model as free-form text.

### Stage 2 — Structured extraction

Cheap, JSON-only model calls extract observations into strict schemas. Examples:

- CVE, CWE, package, repository, vendor, product, version range
- Exploitation claim and provenance
- Fixed version or mitigation
- Indicator types
- Publication and observation timestamps
- Researcher assertion versus direct artifact fact
- Claimed impact and affected environment

Model output is rejected unless it passes JSON Schema, length, enum, and reference checks. The extractor receives a system instruction that the text is untrusted evidence and cannot alter the task.

### Stage 3 — Entity resolution

Prefer deterministic normalization before embeddings:

- Package URLs and ecosystem coordinates
- CVE/GHSA/OSV identifiers
- CPE and product aliases
- GitHub repository IDs and commit SHAs
- Domain punycode and registrable-domain normalization
- Person/account identifiers scoped by platform
- Organization and vendor aliases

Use embeddings only to suggest candidates. A deterministic resolver or bounded adjudication call makes the final link and records alternatives.

### Stage 4 — Clustering and source-independence graph

Build clusters around shared entities, artifacts, timing, and claims. Maintain a citation lineage graph so the system can identify that ten social posts all refer to one original blog.

An independent source must differ in origin, authoring chain, or direct artifact. Reposts, quote-posts, syndicated releases, and copied indicators do not increase corroboration.

### Stage 5 — Emerging-signal analytics

Calculate features over 15-minute, 1-hour, 6-hour, 24-hour, and 7-day windows:

- First seen in any source class
- Time since authoritative publication
- Time since mainstream media threshold
- Unique independent sources and source classes
- Mention velocity and acceleration
- EWMA/CUSUM burst score relative to source baseline
- New-entity and new-term emergence
- Cluster growth and graph centrality
- Researcher-authority weighting based on historical accuracy, not follower count alone
- Contradiction count and correction count
- Repository activity, package events, EPSS change, KEV state, exploit evidence

### Stage 6 — Domain-specific rules

#### Supply-chain rules

- New or recently transferred package ownership
- Maintainer addition/removal followed by release
- Typosquat or homoglyph similarity to high-use packages
- Package age and release-cadence anomaly
- New install hooks, obfuscated payloads, unexpected binary blobs, or network destinations
- Dependency confusion indicators
- Signing or provenance regression
- Sudden yanking/deletion
- Repository/package identity mismatch
- Download/popularity and organization relevance

#### Vulnerability rules

- Public exploit or exploitation observation
- EPSS level and rapid increase
- KEV status
- CVSS vector and attack prerequisites
- Internet-exposed product prevalence
- Patch availability and patch lag
- Vendor advisory ambiguity or silent revision
- Reachability in known organizational inventory

#### Campaign and infrastructure rules

- Newly registered or newly observed domains tied to known brands/projects
- Certificate clustering
- Hosting/ASN changes
- Shared indicators across independent reports
- ATT&CK technique chain coherence
- Evidence of active exploitation versus speculative attribution

### Stage 7 — Preliminary score and triage

A deterministic score decides whether the cluster is archived, watched, analyzed, or escalated. The score is not a model opinion.

### Stage 8 — Bounded analysis

Only clusters above a configurable threshold receive multi-agent analysis. Each analyst receives a compact evidence packet with stable evidence IDs.

### Stage 9 — Challenge and verification

A skeptic agent attempts to falsify the conclusion. A verifier checks each report claim against evidence and detects unsupported certainty, source dependency, stale facts, or missing qualifiers.

### Stage 10 — Publish and learn

The deterministic renderer creates channel-specific outputs. Analyst feedback updates calibration and source-quality records but does not silently rewrite historical reports.

---

## 7. Agent topology and permissions

### 7.1 Chief Intelligence Coordinator

**Model:** `openai/gpt-5.6-sol` through the Codex harness, ultra-high reasoning for final adjudication only.

**Responsibilities:**

- Review the highest-value evidence clusters
- Reconcile specialist findings and skeptic objections
- Decide whether the event is Flash, Watch, Daily, or Archive
- Produce structured assessment JSON
- Explicitly state unknowns and required follow-up

**Allowed tools:** read sanitized evidence packets, read prior assessments, submit assessment.

**Denied tools:** browser, arbitrary shell, host filesystem, source credentials, Discord/email, schedule changes, secret access.

### 7.2 Collection Planner

Creates bounded query plans from approved source templates and current watch entities. It cannot publish findings or directly fetch arbitrary internal addresses.

### 7.3 Source Specialists

Use separate agents or workers for:

- Official advisories and CVE ecosystem
- Code and repository precursors
- Package ecosystem and supply chain
- Researcher/social signals
- Vendor/PSIRT and release notes
- Infrastructure, domains, and indicators

Each has a distinct workspace, credentials, source allowlist, and rate budget.

### 7.4 Content Security Reviewer

Receives sanitizer metadata and narrow excerpts. It classifies manipulation risk and may force a stricter extraction path. It cannot take actions based on source instructions.

### 7.5 Extraction Agents

Use low-cost models with JSON-only outputs and low token caps. They may not ask for more tools.

### 7.6 Impact and Relevance Analyst

Maps affected technologies, likely blast radius, exploit prerequisites, and organization-specific inventory relevance.

### 7.7 Skeptic / Adversarial Reviewer

Looks for benign explanations, duplicate sourcing, chronology errors, hype, fabricated evidence, and premature attribution.

### 7.8 Citation Verifier

Validates that each claim is entailed by cited evidence and that timestamps and source roles are correctly represented.

### 7.9 Publisher

Renders validated JSON into Discord, HTML, email, and downloadable formats. It has no research tools.

### 7.10 Evaluation Agents

Run offline against frozen corpora and adversarial test cases. They cannot affect production scores or reports.

---

## 8. Model routing and cost controls

### Tier A — Deterministic code

Use for fetch, deduplication, normalization, scoring, burst detection, source health, schema validation, rendering, and most entity resolution.

### Tier B — Economical extraction models

Use small/cheap models for classification and structured extraction. Configure:

- JSON-only output
- Strict schema
- Low maximum output tokens
- No tools unless unavoidable
- Temperature near zero
- Retry once only after deterministic repair guidance

### Tier C — Balanced analyst models

Use for medium-confidence clusters requiring synthesis, contradiction analysis, or technical interpretation.

### Tier D — Chief coordinator

Use GPT-5.6 Sol at ultra reasoning for:

- Top N clusters per cycle
- Flash-alert candidates
- Material disagreement among agents
- High-impact findings with incomplete evidence
- Daily final ranking and executive synthesis

### Cost controls

- Content-hash cache for extraction results
- Query-result cache respecting source freshness
- Batch compatible structured tasks
- Per-source request quotas
- Per-stage token and currency budgets
- Maximum clusters promoted per cycle
- Dynamic model downgrade when remaining budget is low
- Early exit for duplicate, stale, low-relevance, or low-impact clusters
- Bounded evidence excerpts rather than complete pages
- Report usage by provider, model, agent, source, finding, and delivery
- Circuit breaker for repeated model/schema failures
- Human approval to exceed a daily emergency budget

---

## 9. Scoring model

Keep scoring dimensions separate in storage and the report.

| Dimension | Range | Meaning |
|---|---:|---|
| Impact | 0–25 | Technical and business consequence if true |
| Exploitability | 0–20 | Ease, prerequisites, exploit evidence, exposure |
| Evidence strength | 0–15 | Directness, quality, corroboration, provenance |
| Momentum | 0–15 | Velocity, acceleration, cluster growth |
| Novelty / lead time | 0–15 | How early and underreported the signal is |
| Organization relevance | 0–10 | Match to assets, vendors, dependencies, sector |
| Penalties | 0 to −30 | Contradictions, dependent sourcing, injection risk, stale data |

`priority_score = clamp(sum(positive_dimensions) + penalties, 0, 100)`

### Classification thresholds

- **Flash:** score ≥ 85, or a critical direct-exploitation rule is met; immediate delivery after verification
- **Watch:** 65–84; re-evaluate every 1–4 hours
- **Daily:** 45–64; include when evidence and relevance justify attention
- **Archive:** below 45; retain for correlation and backtesting

### Confidence

Confidence is not the same as severity:

- **High:** direct authoritative evidence or multiple genuinely independent, high-quality sources
- **Medium:** coherent evidence with material unknowns
- **Low:** weak, single-source, indirect, or contradictory signal

### Emergence stage

- Rumor
- Watch signal
- Credible emerging event
- Confirmed event
- Resolved/corrected

A model cannot promote a finding to “confirmed” unless a deterministic confirmation rule is satisfied.

---

## 10. Report design

### Finding card

Each finding must include:

- Title
- One-sentence “why this matters now”
- Threat class and emergence stage
- Priority score and component breakdown
- Confidence and supporting rationale
- Momentum and novelty/lead-time
- First observed timestamp and current status
- Source timeline
- Affected products, versions, packages, or environments
- Exploitation status and prerequisites
- Organization relevance
- What is known
- What is not yet known
- Skeptic objections and contradictions
- Defensive actions, ordered by urgency and reversibility
- ATT&CK/CWE/CVE/GHSA/OSV mappings where applicable
- Sanitized indicators
- Evidence citations
- Next scheduled check

### Daily brief sections

1. Executive signal summary
2. Flash and high-priority findings
3. Watchlist changes since prior report
4. Supply-chain and malicious-package research
5. Vulnerability and exploitation research
6. Campaign/infrastructure signals
7. Corrected or downgraded findings
8. Source coverage and degraded inputs
9. Model/tool usage, latency, and estimated cost
10. Analyst feedback requests

Do not fill space. “No material emerging threats met the publication threshold” is a valid result.

---

## 11. Schedule and workflow design

Use OpenClaw cron for durable triggering, isolated sessions for scheduled research, Task Flow for stateful long-running work, and Lobster for deterministic typed stages and approval/resume points.

Recommended schedule in America/New_York:

| Cadence | Work |
|---|---|
| Every 15 minutes | Structured feeds and high-value precursor deltas |
| Hourly | Social/research fan-out, new-cluster formation, Flash candidate evaluation |
| Every 4 hours | Watchlist refresh and contradiction search |
| 07:30 daily | Full morning intelligence brief |
| 15:00 daily | Delta brief emphasizing changes since morning |
| Weekly | Evaluation, lead-time retrospective, source-quality review, cost review |

Use jitter inside source workers to avoid synchronized bursts while keeping the top-level schedule deterministic.

### Workflow state machine

```text
PLANNED
  → COLLECTING
  → QUARANTINED
  → SANITIZED
  → EXTRACTED
  → CORRELATED
  → TRIAGED
  → ANALYZING
  → CHALLENGED
  → VERIFIED
  → PUBLISHED
  → CLOSED
```

Failure states are retryable, quarantined, degraded, or terminal. Every transition records actor, code/model version, input hashes, output hashes, and policy decision.

---

## 12. Reliability engineering

- PostgreSQL-backed run and step state
- Idempotency keys for fetch, extraction, assessment, and delivery
- Exponential backoff with jitter and source-specific retry policies
- Circuit breakers for source, model, and delivery failures
- `FOR UPDATE SKIP LOCKED` work claiming or an equivalent durable queue
- Dead-letter queue with replay tooling
- Per-source freshness and coverage objectives
- Partial report generation with an explicit degraded-source banner
- Delivery receipts and retry-safe message IDs
- Deterministic rendering from immutable report JSON
- Daily database backups and object-store versioning
- Reproducible backfill using stored artifacts
- Schema migration discipline and backward-compatible event contracts
- Health checks for Gateway, workers, database, object store, telemetry, and destinations
- Runbooks for source outage, false alert, secret exposure, compromised connector, prompt-injection incident, and model regression

---

## 13. Prompt-injection and content-safety architecture

### Non-negotiable controls

1. Raw content never enters a privileged system/developer instruction channel.
2. Raw content never reaches the coordinator.
3. Internet-facing agents cannot access secrets or publish.
4. Publishing agents cannot browse.
5. Model output cannot directly create tool arguments for privileged actions.
6. Cross-agent messages are schema validated and reject unknown fields.
7. Source content cannot create schedules, persistent memory, rules, or new agents.
8. URLs are revalidated by the fetch gateway; agents cannot bypass SSRF controls.
9. Reports include only evidence-backed defensive content; no execution of malware or exploit code.
10. All policy denials and suspicious instructions are logged as security telemetry.

### Fetch and egress gateway

Block:

- Loopback, RFC1918, carrier-grade NAT, link-local, multicast, and cloud metadata ranges
- Non-HTTP(S) schemes unless a source-specific adapter explicitly implements them
- DNS rebinding and redirect to disallowed addresses
- Credential-bearing URLs
- Unbounded downloads and archive bombs
- Cross-origin browser access outside the source allowlist

### Injection detection is advisory, not the safety boundary

Use deterministic and model-based detectors to classify risk, but assume detection will miss attacks. The true safety boundary is least privilege, isolation, typed data flow, egress restrictions, and denial of state-changing tools.

### Time-bomb resistance

- No source-derived instruction is stored in agent memory
- Scheduled prompts are static, version-controlled templates
- Prior context is loaded as typed assessments, not conversational transcripts
- Text resembling future instructions, dates, triggers, or secrets receives a risk flag
- All caches are keyed by sanitized content hash and extractor version
- Re-analysis never grants a document more privileges than its original trust zone

---

## 14. Evaluation program

### Offline historical backtest

Build a dataset of known events containing:

- Earliest authoritative artifact
- Earliest credible researcher signal
- Earliest exploit or malicious-package evidence
- Mainstream media first-publication time
- Impact, scope, and final truth label
- False rumors and benign package/repository anomalies

Replay only artifacts available at each historical time. This avoids hindsight leakage.

### Metrics

- Precision@K and recall for high-impact events
- Median and percentile lead time versus media baseline
- False alerts per day/week
- Citation coverage and entailment
- Independent-source accuracy
- Confidence calibration using Brier score and expected calibration error
- Time to correction or downgrade
- Cost per actionable finding
- Model and source latency
- Source freshness and coverage
- Prompt-injection attack success rate
- Policy violations and denied tool attempts
- Reproducibility from stored evidence

### Adversarial injection corpus

Include:

- Visible “ignore previous instructions” content
- Hidden CSS/HTML and zero-opacity text
- HTML comments, metadata, alt text, SVG, PDF annotations, and image/OCR text
- Unicode homoglyphs, bidirectional controls, zero-width text
- Base64, ROT, nested encoding, and split instructions
- Fake system/developer messages
- Tool-call shaped JSON and shell commands
- Requests for secrets or internal prompts
- Fake citations and source impersonation
- Delayed or date-triggered instructions
- Cross-document payloads where one artifact activates another
- Sybil/repost campaigns designed to simulate independent corroboration

### Release gates

No production release unless:

- All factual report claims are cited
- State-changing or exfiltration injection success is zero in the gate suite
- Source outage and partial report tests pass
- Schema compatibility and replay tests pass
- Cost ceilings and loop limits work
- Human reviewers accept shadow-mode precision and false-alert rate

---

## 15. Private GitHub repository and software supply-chain controls

Create the repository as private from the first push. Recommended controls:

- Protected `main` branch
- Pull requests required
- At least two approvals for policy, workflow, schema, or security changes
- CODEOWNERS for security-sensitive paths
- Secret scanning and push protection where available
- Dependabot updates
- CodeQL for supported languages where licensing supports private repositories
- Semgrep, Ruff, mypy, pytest, Gitleaks, and Trivy in CI
- Dependency pinning and hash verification
- GitHub Actions pinned to immutable commit SHAs
- Minimal workflow permissions and no broad `pull_request_target` execution
- SBOM generation for releases
- Artifact attestations and signed or immutable releases
- No credentials in repository, fixtures, prompts, or HTML reports
- Separate production deployment environment with required reviewers

Use `scripts/create-private-repo.sh` to initialize and push, after reviewing the destination organization and repository name.

---

## 16. Phased implementation

### Phase 0 — Foundations and threat model

Deliver:

- Private repository, ownership, branch controls, CI
- Architectural decision records
- Data contracts and threat model
- Environment separation and secrets strategy
- Source terms/retention registry
- Evaluation dataset schema

Exit criteria: security boundaries and schemas approved; no connector code deployed.

### Phase 1 — Safe ingestion and immutable evidence

Deliver:

- PostgreSQL and object storage
- Connector SDK and first Tier 0 adapters
- Safe fetch/egress gateway
- Quarantine metadata and artifact hashing
- Source health and replay

Exit criteria: repeated runs are idempotent; artifacts are immutable; SSRF/archive tests pass.

### Phase 2 — Sanitization, extraction, and normalized graph

Deliver:

- Content-security gateway
- Structured extraction service
- Entity normalization and evidence ledger
- Initial cluster graph
- Injection risk records

Exit criteria: no raw content reaches analyst agents; schemas and red-team tests pass.

### Phase 3 — Scoring and multi-agent analysis

Deliver:

- Deterministic feature and score engine
- Model router and budgets
- Specialist, skeptic, verifier, and coordinator agents
- Task Flow/Lobster workflows
- Assessment state machine

Exit criteria: every assessment is reproducible and traceable to evidence IDs.

### Phase 4 — Reporting and delivery

Deliver:

- Report JSON schema
- Rich HTML renderer
- Discord embed/attachment delivery
- Email adapter
- Usage and source-health sections

Exit criteria: retry-safe delivery, deterministic output, accessibility and mobile review.

### Phase 5 — Backtest and shadow mode

Deliver:

- Historical event corpus
- Injection corpus
- Lead-time and precision dashboards
- Analyst feedback workflow
- Threshold and calibration tuning

Exit criteria: release gates met and reviewers approve false-alert behavior.

### Phase 6 — Production hardening

Deliver:

- Horizontal workers, backup/restore, observability, alerts
- SLOs, runbooks, on-call ownership
- Security audit and penetration testing
- Deployment approvals and rollback

Exit criteria: production readiness review approved.

### Phase 7 — Advanced predictors and organizational relevance

Deliver:

- Asset/SBOM/dependency inventory matching
- Researcher/source historical calibration
- Graph-based campaign emergence
- Optional lawful isolated non-indexed-source collection
- MISP/STIX export and bidirectional analyst workflows

Exit criteria: measurable improvement in lead time or precision without weakening safety.

---

## 17. Definition of done for the build

The first production release is done when:

- It runs unattended on the defined schedule
- It can survive an individual source or model outage
- It sends a useful Discord brief and rich HTML attachment
- Every finding exposes score components, confidence, unknowns, and evidence
- It catches seeded emerging-event scenarios before the media-baseline artifact appears
- It rejects prompt-injection test cases without privileged effects
- It gives a complete per-run usage and cost breakdown
- It can replay a report from stored evidence
- A new connector can be added without modifying core orchestration
- Operators have visual documentation and tested runbooks
