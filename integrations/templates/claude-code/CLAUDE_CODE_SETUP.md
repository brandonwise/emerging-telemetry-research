# Claude Code adapter

The generated `CLAUDE.md` and project skill teach Claude Code to invoke the same deterministic CLI
used by every other deployment. They do not expose discovery credentials to prompts.

1. Copy `radar.env.example` to `radar.env` and configure secrets outside source control.
2. Run `./run-radar.sh` directly, or ask Claude Code to use the `threat-radar` project skill.
3. Schedule the shell script with cron, systemd, launchd, or your CI runner.
4. Keep external delivery in a separate reviewed step.

Headless automation can invoke Claude Code print mode, but Claude is not required for collection,
verification, storage, rendering, or the portal.
