name: telemetry-research-portable
steps:
  - id: collect_verify_render
    command: ./run-research.sh

  - id: index_analytics
    command: >-
      uv run emerging-telemetry-research analytics sync
      --reports reports/generated
      --database state/research.db
      --json
