# OpenClaw adapter

This adapter keeps OpenClaw responsible only for scheduling and reviewed delivery. The threat
engine, storage, verification, and report rendering stay portable.

1. Copy `radar.env.example` to `radar.env` and provide secrets through OpenClaw's secret store.
2. Run `./run-radar.sh`.
3. Inspect the emitted local delivery plan before connecting any destination.
4. Add `openclaw/workflows/threat-radar-portable.lobster` to an isolated cron job.

The included workflow does not send messages. Add delivery only through a fixed-destination,
idempotent tool with an approved threat model.
