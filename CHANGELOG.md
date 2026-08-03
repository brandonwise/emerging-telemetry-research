# Changelog

All notable changes to Emerging Telemetry Research are recorded here. The project follows Semantic Versioning
for release identifiers while it remains private.

## [1.1.0rc1] - 2026-08-03

### Changed

- Standardized the product and onboarding language on Emerging Telemetry Research, research
  missions, and research objectives.
- Added `--result-type` as the primary mission-authoring option while retaining `--outcome` as a
  backward-compatible alias.
- Replaced command-line-only onboarding with an authenticated loopback control plane covering
  private initialization, harness selection, keyring secrets, mission creation, source review,
  hash-bound deployment approval, activation, scheduling, and corrective feedback.
- Generated adapters now layer the private workspace before optional platform overrides and
  preserve the operator's OpenClaw model unless one is explicitly selected.

### Added

- Harness discovery and expiring real-provider contract-test receipts from either the CLI or setup
  control plane, with explicit provider-quota acknowledgement.
- Governed site-search, safe HTTPS page, and same-site RSS/Atom mission sources.
- Fast-scan, balanced, and deep-research workflow templates.
- A cross-platform durable scheduler with atomic leases, recovery, bounded retry, and pause/resume.
- Additive private-config upgrades and installed-wheel fixture certification.

### Security

- One-time setup login tokens, HttpOnly strict cookies, CSRF, loopback/Host enforcement, restrictive
  browser policy, bounded forms, no rendered credential values, and disposable resource-bounded
  parsing for untrusted page and feed content.

## [1.0.0] - 2026-08-03

### Added

- Mission-driven research workflows and a guided mission builder.
- Portable and production storage profiles.
- Cross-platform private workspace initialization, diagnostics, PowerShell runner, and OS-keyring,
  environment, or owner-only file secret references.
- Provider-neutral bounded agent reviews with preference routing, retries, fallbacks, and circuit
  breaking.
- Allowlisted collector and agent-provider plugin registries.
- Durable hash-bound graph checkpoints and bounded repeated-state loops.
- Proposal-only self-improvement advice across coverage, calibration, reliability, routing,
  prompts, cost, and security.
- Read-only analytics and report portal.

### Security

- Approval-gated collection and external delivery.
- Hash-bound, expiring local capability approvals for collection, delivery, and improvement apply.
- DNS-pinned HTTPS fetching and resource-bounded cross-platform parser subprocesses.
- Syndication-aware independent-source counting for research missions.
- Hostile-content sanitation and schema-validated agent boundaries.
- Immutable evidence, report, and delivery receipts.

## [0.1.0] - 2026-07-31

### Added

- Initial emerging-threat research vertical slice.
