name: threat-radar
args:
  mode:
    default: "structured-ingest"
  edition:
    default: "none"
steps:
  - id: create_run
    command: threat-radar run create --mode "$LOBSTER_ARG_MODE" --edition "$LOBSTER_ARG_EDITION" --json

  - id: collect
    command: threat-radar collect --run-from-stdin --json
    stdin: $create_run.json

  - id: quarantine
    command: threat-radar quarantine --run-from-stdin --json
    stdin: $collect.json

  - id: sanitize
    command: threat-radar sanitize --run-from-stdin --json
    stdin: $quarantine.json

  - id: extract
    command: threat-radar extract --run-from-stdin --json
    stdin: $sanitize.json

  - id: correlate
    command: threat-radar correlate --run-from-stdin --json
    stdin: $extract.json

  - id: score
    command: threat-radar score --run-from-stdin --json
    stdin: $correlate.json

  - id: analyze
    command: threat-radar analyze --run-from-stdin --json
    stdin: $score.json

  - id: challenge
    command: threat-radar challenge --run-from-stdin --json
    stdin: $analyze.json

  - id: verify
    command: threat-radar verify --run-from-stdin --json
    stdin: $challenge.json

  - id: render
    command: threat-radar report render --run-from-stdin --json
    stdin: $verify.json

  - id: flash_approval
    command: threat-radar report approval-preview --json
    stdin: $render.json
    condition: $render.json.requires_human_approval
    approval: required

  - id: deliver
    command: threat-radar report deliver --json
    stdin: $render.json
    condition: $render.json.auto_publish || $flash_approval.approved

  - id: finalize
    command: threat-radar run finalize --json
    stdin: $deliver.json
