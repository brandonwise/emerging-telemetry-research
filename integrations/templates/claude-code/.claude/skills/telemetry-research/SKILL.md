---
name: telemetry-research
description: Run and inspect the portable evidence-backed Emerging Telemetry Research workflow.
---

# Telemetry Research

1. Confirm `BRAVE_API_KEY` and `XAI_API_KEY` exist without printing their values.
2. Run `./run-research.sh`.
3. Require exit code zero and parse its final JSON object.
4. Report the report ID, finding count, degraded sources, report paths, and local delivery status.
5. Do not send or post the report. External delivery requires a separately approved adapter.

For history, run `uv run emerging-telemetry-research analytics sync --json`. For the portal, use
`scripts/run-portal.sh` on loopback or `scripts/run-portal.sh --lan` with a configured token.
