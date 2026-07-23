# ADR 0001: PostgreSQL owns workflow state and the first durable queue

Status: accepted

## Decision

Use PostgreSQL 16 for relational evidence, run state, audit records, and work claiming with
`FOR UPDATE SKIP LOCKED`. OpenClaw sessions are disposable execution context, not durable state.

## Why

The first release does not need another broker. Keeping workflow state and work claims in one
transaction reduces split-brain failure modes and makes replay easier to audit.

## Consequences

- Queue handlers must be idempotent.
- Every mutation carries a run ID, step ID, and idempotency key.
- A dedicated broker requires a later ADR and load evidence.
