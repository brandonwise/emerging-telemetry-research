name: threat-radar-portable
steps:
  - id: collect_verify_render
    command: ./run-radar.sh

  - id: index_analytics
    command: >-
      uv run outcome-radar analytics sync
      --reports reports/generated
      --database state/radar.db
      --json
