# ADR 0006: Collection and external delivery default off

Status: accepted

## Context

The supplied source configuration enabled several collectors before the threat model had an
approval record. That conflicts with the build sequence and the stricter security boundary.

## Decision

All sources, schedules, and external delivery remain disabled until an approval ID is recorded and
deployment checks confirm source terms, egress isolation, role credentials, and policy validity.
Frozen fixtures are allowed in shadow mode.

## Consequences

- Development and evaluation can proceed without internet-facing agents.
- Enabling collection is a reviewed configuration change.
- The runtime fails closed if an enabled source lacks an approval ID.
