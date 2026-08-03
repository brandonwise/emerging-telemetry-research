# OpenClaw adapter

This adapter keeps OpenClaw responsible only for scheduling and reviewed delivery. The threat
engine, storage, verification, and report rendering stay portable.

1. Copy `research.env.example` to `research.env` and provide secrets through OpenClaw's secret store.
2. From the repository root, run `make openclaw-agents-check`. If the role agents are absent, review
   and run `make openclaw-agents-install`, restart the OpenClaw gateway if the installer reports a
   change, then repeat the check.
3. Run `./run-research.sh`.
4. Set `ETR_AGENT_ADAPTER=openclaw` and `ETR_AGENT_MODE=shadow` to execute the bounded role
   graph through the configured `research-*` agents.
5. Inspect the emitted local delivery plan and `agent_reviews` before connecting any destination.
6. Add `openclaw/workflows/telemetry-research-portable.lobster` to an isolated cron job.

The included workflow does not send messages. Agent turns use unique run/finding sessions and have
no delivery authority. The installer pins each role workspace and model, clears its skill list,
disables memory search, allows only session status, and explicitly denies file, shell, browser,
network, messaging, scheduler, gateway, and delegation tools. Add delivery only through a
fixed-destination, idempotent tool with an approved threat model.
