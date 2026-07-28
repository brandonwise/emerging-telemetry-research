# Threat model approval

Status: approved

Collection authorization: enabled

External delivery authorization: disabled

Approval reference: discord:channel:1476283808587321451:message:1530156178129289346

Approver: bwise (Discord user 398959546116079616)

Approval timestamp: 2026-07-24T10:14:21Z

Reviewed architecture commit: 984ee9c

Environment: Brandon Wise local OpenClaw production instance

Residual-risk acceptance: Read-only collection from the approved sources below, bounded paid API
usage, short-lived discovery results, immutable authoritative evidence, and publication to the
local database/private read-only website are accepted. Routine Discord delivery is disabled.
Browser-based collection, arbitrary web execution, authenticated vendor portals, malware
detonation, and autonomous defensive changes remain out of scope.

Delivery amendment: On 2026-07-28, the approver requested DB/private-website publication only and
revoked routine delivery to the Discord `#news` channel.

Local inference amendment: On 2026-07-28, the approver requested local inference to improve the
workflow. Approval is limited to the ADR 0011 shadow-mode Nomic embedding observer: loopback-only,
zero publication authority, no persisted vectors, and fail-open to the deterministic pipeline.

## Approval scope

Approval covers `THREAT_MODEL.md`, `SECURITY.md`, the ADRs under `docs/adr/`, and the following
initial source classes:

- CISA KEV
- CVE List V5 and NVD
- FIRST EPSS
- OSV
- GitHub Global Security Advisories
- Brave Search API for discovery only; API responses are not retained as evidence
- xAI server-side X Search against the curated account allowlist for discovery only; model output
  and raw X posts are not promoted without authoritative corroboration

Approval does not cover browser-based collection, unrestricted social search, authenticated vendor
portals, Tor, malware detonation, or organization inventory.

## Required sign-off record

This approval record contains:

- approver identity
- approval timestamp
- reviewed Git commit
- approved source IDs
- approved environment
- residual-risk acceptance

Configuration, egress, credentials, source terms, and production-readiness gates must also pass
before the first external delivery.
