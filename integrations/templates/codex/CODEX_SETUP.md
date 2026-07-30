# Codex adapter

The generated `AGENTS.md` and repository skill keep Codex focused on operating the same portable
CLI as OpenClaw, Claude Code, and generic automation.

1. Copy `radar.env.example` to `radar.env` and configure secrets outside source control.
2. Set `RADAR_AGENT_ADAPTER=codex`, `RADAR_AGENT_MODE=shadow`, and an approved
   `RADAR_AGENT_MODEL`. The adapter runs ephemeral, read-only Codex turns with the assessment
   schema and no approval escalation.
3. Run `./run-radar.sh` directly or use `codex exec` with the repository instructions.
4. Schedule the shell script with cron, systemd, launchd, or CI.
5. Keep external delivery in a separate reviewed step.

Codex is an optional operator and reasoning surface; the core workflow does not depend on it.
