---
name: threat-radar
description: Run and inspect the portable evidence-backed Emerging Threat Radar workflow.
---

# Threat Radar

1. Confirm `BRAVE_API_KEY` and `XAI_API_KEY` exist without showing their values.
2. Run `./run-radar.sh`.
3. Verify the exit code and parse the emitted JSON.
4. Return the report ID, finding count, degraded sources, report paths, and local delivery status.
5. Never send the report externally unless the user authorizes a configured destination.

Use `uv run outcome-radar analytics sync --json` to rebuild history. Start the read-only portal with
`scripts/run-portal.sh`; `--lan` additionally requires a strong access token.
