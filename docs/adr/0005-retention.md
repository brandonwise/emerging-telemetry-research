# ADR 0005: Evidence retention is explicit and source-aware

Status: accepted

## Decision

Default retention is 365 days for raw and sanitized evidence, subject to source terms. Reports,
claim lineage, policy decisions, and security events are retained for 730 days. A legal hold
overrides deletion. No source is enabled until its terms and retention decision are approved.

## Why

Replay needs durable evidence, but source licenses and sensitive indicators can require shorter
retention.

## Consequences

- The source registry records terms status, review date, and retention.
- Deletion is an audited lifecycle operation, not an ad hoc file removal.
- Production retention needs owner and legal approval.
