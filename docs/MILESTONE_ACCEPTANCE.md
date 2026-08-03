# Milestone design and acceptance record

This record distinguishes implemented shadow-mode controls from release evidence that requires an
approved deployment. Security gates remain closed when evidence is missing.

## Milestone 0 — repository and decisions

Design: a private, protected GitHub repository with immutable CI dependencies and explicit ADRs.
The local repository includes CODEOWNERS, Dependabot, pinned CI/CodeQL/Gitleaks/Trivy actions, a
locked Python environment, and ADRs for PostgreSQL, object storage, egress, models, retention, and
approval-gated collection.

Acceptance:

- Repository validator rejects floating Actions and container `latest` tags.
- Required ADRs, contracts, approval records, and security configs must exist.
- Distributable defaults mechanically force sources, schedules, delivery, and self-mutation off.

External gate: private GitHub creation, branch protection, and a local hash-bound deployment
approval. `THREAT_MODEL_APPROVAL.md` is only a review template.

## Milestone 1 — data plane and safe collection

Design: PostgreSQL is the durable queue and system of record; S3-compatible storage keeps
content-addressed immutable artifacts. All network access crosses one source-scoped fetch service.

Acceptance:

- Migrations cover runs, steps, sources/cursors/health, artifacts, observations, entities,
  relationships, clusters, evidence/lineage, assessments/claims, reports, usage, delivery,
  policy/security events, API idempotency, and dead letters.
- Work and dead-letter claims use `FOR UPDATE SKIP LOCKED`.
- API idempotency and record persistence share one PostgreSQL transaction.
- Safe-fetch tests cover SSRF, redirect revalidation, response limits, redacted headers, and
  nonpositive rate-limit rejection.
- Frozen collection is content-addressed and replayable.

Deployment gate: execute the PostgreSQL integration test and S3 versioning/retention checks in the
target environment. CI provisions a disposable PostgreSQL service for this test.

## Milestone 2 — content-security gateway

Design: deterministic parsing is the primary boundary. Injection detection is a risk signal layered
on active-content removal, bounded outputs, schema validation, isolation, and least privilege.

Acceptance:

- Visible, hidden, comment, attribute, zero-width, bidi, base64, delayed, and nested injection
  variants produce no model access at high/critical risk.
- Executable MIME types, malformed inputs, traversal paths, excessive nesting, member counts, and
  decompression ratios are rejected.
- Original/sanitized hashes, decisions, patterns, and risk are present in the audit lineage.

The live pipeline uses the fail-closed text-artifact scanner for its text-only MIME allowlist and
rejects executable signatures and the EICAR marker. Binary document, media, or archive extraction
remains outside this release boundary and requires a separately approved sandbox/scanner profile.

## Milestone 3 — normalization, lineage, and scoring

Design: normalize identifiers deterministically, group evidence by originating lineage, compute
bounded features, and keep organizational relevance behind an adapter.

Acceptance:

- CVE, GHSA, OSV, package/PURL, repository, domain, account, and indicator normalization tests.
- Ten syndicated observations count as one origin.
- Frozen Watch/Flash fixtures exercise novelty, exploitation, independence, impact, and demo
  inventory relevance.

## Milestone 4 — bounded agents and model router

Design: agents exchange strict evidence and assessment objects only. OpenClaw tool policies remove
browsing, shell, schedules, secrets, and delivery from analytical roles. The chief uses
`openai/gpt-5.6-sol` only for promoted/disputed coordination.

Acceptance:

- The fixture review chain executes specialist, skeptic, citation verifier, then coordinator.
- Model routing plans daily/run/cluster budgets and a Flash reserve; provider usage is persisted for
  enforcement and operator review.
- The chief has no raw-artifact, browser, shell, message, schedule, memory, or administrative tool.
- The publisher has only the fixed-destination verified-delivery tool.

Deployment gate: validate `openclaw/openclaw.example.json5` against the exact target gateway schema,
then run `openclaw doctor --deep`.

## Milestone 5 — reports and delivery

Design: report JSON is the source of truth. HTML and Discord plans are deterministic views. Delivery
is a separate retry-safe side effect and cannot select a destination at runtime.

Acceptance:

- Unsupported or uncited claims are blocked before rendering.
- HTML auto-escapes source-derived strings, carries a restrictive CSP, uses no remote assets, and
  replays byte-for-byte.
- Reports show degraded sources, confidence, score dimensions, knowns/unknowns, skeptic review,
  evidence IDs, next checks, usage, and estimated cost.
- The OpenClaw delivery plugin verifies report state, constrains attachment paths, fixes the
  Discord destination in config, and stores idempotent receipts.

External gates: browser-rendered report review and a private Discord delivery dry run.

## Milestone 6 — evaluation and shadow mode

Design: frozen event time controls source visibility; the media baseline appears only in the later
fixture. Injection variants are generated automatically.

Acceptance:

- A degraded source still yields a verified report.
- An early Watch precedes the media fixture.
- Hostile-content privileged effects and model access are zero.
- Syndication yields one origin.
- Unsupported claims are rejected.
- A Flash candidate receives skeptic and citation review.
- JSON, HTML, and audit logs replay byte-for-byte.
- Cost attribution is complete.

Release gate: accumulate the precision, citation-entailment, calibration, independently
baseline-backed lead-time, reliability, and cost window defined in `EVALS.md`; do not enable Flash
delivery before it passes. Lead-time remains unreported while the approved baseline collector is
disabled.

## Milestone 7 — production hardening

Design: bounded OpenTelemetry labels, Prometheus alert rules, PostgreSQL dead letters, partial
reports, immutable restore verification, and explicit incident/rollback procedures.

Acceptance:

- Local immutable evidence backup/restore reproduces JSON, HTML, and audit output byte-for-byte.
- Dead-letter replay preserves input hashes and generates deterministic idempotency keys.
- Alerts cover workflow, source, model, delivery, and critical security events.
- Runbook procedures never broaden egress or weaken a security gate to recover service.

Deployment gates: database point-in-time restore, object-lock restore, alert delivery, chaos,
rollback, and OpenClaw deep-audit evidence from the target environment.

## Milestone 8 — universal research missions

Design: security becomes a built-in mission pack on a universal research contract. Plain-language
intent compiles into bounded sources and queries, evidence rules, deterministic scoring, mission-
specific role briefs, output limits, and evaluation targets. The proven five-role graph and engine
safety controls remain fixed.

Acceptance:

- The mission schema rejects unknown fields, invalid score totals, changed role dependencies,
  unapproved active sources, and external delivery.
- The portal provides a responsive mission builder, exact plan preview, and downloadable draft.
- Draft missions run offline fixtures; live runs require a source-by-source activation approval.
- Activation writes base and active hashes plus an exact rollback contract.
- The developer-product opportunity fixture produces a cited outcome from three source types.
- Mission reports remain immutable, use mission vocabulary, and keep ranking in code.
- Unregistered sources, mismatched surfaces, stale evidence, unsafe URLs, single-source clusters,
  and injected source instructions cannot produce an outcome.
- Useful, not useful, and needs-work feedback is immutable and replaces proxy usefulness in
  mission evaluation.
- Security and developer-product opportunity packs validate against the same engine contract.

External gate: approve the live source plan for each mission separately. One mission's approval
never grants collection authority to another.
