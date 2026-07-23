# Threat model approval

Status: pending

Collection authorization: disabled

External delivery authorization: disabled

## Approval scope

Approval covers `THREAT_MODEL.md`, `SECURITY.md`, the ADRs under `docs/adr/`, and the following
initial source classes:

- CISA KEV
- CVE List V5 and NVD
- FIRST EPSS
- OSV
- GitHub Global Security Advisories

Approval does not cover browser-based discovery, social platforms, authenticated vendor portals,
Tor, malware detonation, or organization inventory.

## Required sign-off record

Before collection is enabled, replace `pending` with an immutable approval reference containing:

- approver identity
- approval timestamp
- reviewed Git commit
- approved source IDs
- approved environment
- residual-risk acceptance

An approval does not enable collection by itself. Configuration, egress, credentials, source terms,
and production-readiness gates must also pass.
