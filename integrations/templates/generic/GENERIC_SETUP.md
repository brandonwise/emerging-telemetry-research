# Generic adapter

This is the lowest-common-denominator deployment: Python 3.12, `uv`, Brave, xAI, SQLite, and the
local filesystem. Agent execution is optional and uses an OpenAI-compatible HTTPS endpoint.

1. Copy `radar.env.example` to `radar.env`.
2. Set `BRAVE_API_KEY` and `XAI_API_KEY` using your secret manager.
3. Run `./run-radar.sh`.
4. Schedule it daily with the scheduler already used by your host.
5. Start the portal on loopback with `scripts/run-portal.sh`, or explicitly choose authenticated
   private-LAN mode with `scripts/run-portal.sh --lan`.

Example cron entry for 7:30 AM local time:

```cron
30 7 * * * cd /opt/threat-radar && ./run-radar.sh >> state/scheduler.log 2>&1
```

The generated runner produces a file-only delivery plan. Integrate email, chat, or ticketing as a
separate reviewed consumer of that plan; do not put delivery credentials in the collection process.

To execute bounded reviews, set `RADAR_AGENT_ADAPTER=openai-compatible`,
`RADAR_AGENT_MODE=shadow`, `RADAR_AGENT_BASE_URL`, `RADAR_AGENT_MODEL`, and
`RADAR_AGENT_API_KEY`. Use `plan` mode when no model endpoint is available.

Optional approved direct access uses `REDDIT_ACCESS_TOKEN` plus `REDDIT_USER_AGENT`, or
`TIKTOK_RESEARCH_ACCESS_TOKEN`. Credentials alone do not enable collection: update the matching
source approval and `config/discovery.yaml` flag as described in `docs/SETUP.md`.
