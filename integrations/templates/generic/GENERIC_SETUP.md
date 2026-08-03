# Generic adapter

This is the lowest-common-denominator deployment: Python 3.12–3.14, `uv`, Brave, xAI, SQLite, and the
local filesystem. Agent execution is optional and uses an OpenAI-compatible HTTPS endpoint.

1. Run `emerging-telemetry-research setup init --profile portable` at the project root.
2. Copy `research.env.example` to `research.env` and use only secret references.
3. Generate, review, and apply a local deployment approval.
4. Run `./run-research.sh` on POSIX or `./run-research.ps1` in PowerShell.
5. Schedule it with the scheduler already used by your host.
6. Start the portal on loopback with `scripts/run-portal.sh`, or explicitly choose authenticated
   private-LAN mode with `scripts/run-portal.sh --lan`.

Example cron entry for 7:30 AM local time:

```cron
30 7 * * * cd /opt/emerging-telemetry-research && ./run-research.sh >> state/scheduler.log 2>&1
```

The generated runner produces a file-only delivery plan. Integrate email, chat, or ticketing as a
separate reviewed consumer of that plan; do not put delivery credentials in the collection process.

To execute bounded reviews, set `ETR_AGENT_ADAPTER=openai-compatible`,
`ETR_AGENT_MODE=shadow`, `ETR_AGENT_BASE_URL`, `ETR_AGENT_MODEL`, and
`ETR_AGENT_API_KEY_REF`. Use `plan` mode when no model endpoint is available.

Optional approved direct access uses `REDDIT_ACCESS_TOKEN` plus `REDDIT_USER_AGENT`, or
`TIKTOK_RESEARCH_ACCESS_TOKEN`. Credentials alone do not enable collection: update the matching
source approval and `config/discovery.yaml` flag as described in `docs/SETUP.md`.
