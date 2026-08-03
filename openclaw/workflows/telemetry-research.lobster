name: telemetry-research
args:
  mode:
    default: "structured-ingest"
  edition:
    default: "morning"
steps:
  - id: validate_mode
    command: >-
      uv run emerging-telemetry-research run create
      "$LOBSTER_ARG_MODE"
      --edition "$LOBSTER_ARG_EDITION"
      --json

  - id: live_run
    command: scripts/run-live.sh
