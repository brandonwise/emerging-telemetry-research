# Claude Code adapter

The generated `CLAUDE.md` and project skill teach Claude Code to invoke the same deterministic CLI
used by every other deployment. They do not expose discovery credentials to prompts.

1. Copy `research.env.example` to `research.env` and configure secrets outside source control.
2. Set `ETR_AGENT_ADAPTER=claude`, `ETR_AGENT_MODE=shadow`, and an approved
   `ETR_AGENT_MODEL`. The adapter uses bare, no-session, tool-free structured-output turns.
3. Run `./run-research.sh` directly, or ask Claude Code to use the `telemetry-research` project skill.
4. Schedule the shell script with cron, systemd, launchd, or your CI runner.
5. Keep external delivery in a separate reviewed step.

Headless automation can invoke Claude Code print mode, but Claude is not required for collection,
verification, storage, rendering, or the portal.
