name: threat-radar
args:
  mode:
    default: "structured-ingest"
  edition:
    default: "none"
steps:
  - id: validate_mode
    command: >-
      uv run threat-radar run create
      "$LOBSTER_ARG_MODE"
      --edition "$LOBSTER_ARG_EDITION"
      --json

  - id: live_run
    command: scripts/run-live.sh
