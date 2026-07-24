# ADR 0009: Portable analytics and read-only portal

Status: accepted

## Context

The production workflow used PostgreSQL, S3-compatible evidence storage, OpenTelemetry, and an
OpenClaw-specific delivery boundary. That is appropriate for the approved deployment but too heavy
for personal evaluation and too coupled for Claude Code, Codex, or agent-free operation.
OpenTelemetry also does not provide a durable user-facing report archive.

## Decision

1. Implement an immutable SQLite repository with the same application contract as PostgreSQL.
2. Add a rebuildable SQLite analytics index for report snapshots, findings, source health,
   usage/cost, and bounded content-free telemetry events.
3. Add a portable live profile using Brave, xAI X Search, official corroboration sources, SQLite,
   local content-addressed objects, and file-only delivery plans.
4. Treat OpenClaw, Claude Code, Codex, and generic scheduling as thin adapters around the same CLI.
5. Add an optional server-rendered, read-only portal. It binds loopback by default. Private-LAN
   mode always requires private-source filtering and uses strong token authentication by default.
   Trusted-network operators may explicitly disable authentication without weakening the network
   boundary; the service never disables authentication implicitly.
6. Keep external delivery separate from portable collection and disabled by default.

## Consequences

- A new deployment needs only Python, `uv`, two discovery credentials, and local disk.
- PostgreSQL/S3 remain the stronger production profile and are not removed.
- Analytics are derived and can be rebuilt from immutable reports.
- The portal cannot mutate workflows, thresholds, reports, delivery, or feedback.
- Disabled authentication is acceptable only on a trusted private segment and must be reversed
  before public exposure, port forwarding, or broadening the allowed networks.
- Plain HTTP LAN sessions are appropriate only on a trusted or encrypted network; TLS is supported
  and recommended.
- Platform changes do not fork threat logic or report contracts.
