name: threat-radar
args:
  mode:
    default: "structured-ingest"
  edition:
    default: "none"
steps:
  - id: create_run
    command: >-
      uv run threat-radar run create
      "$LOBSTER_ARG_MODE"
      --edition "$LOBSTER_ARG_EDITION"
      --json

  - id: live_collection_gate
    command: uv run threat-radar run blocked-live-collection
    stdin: $create_run.json
