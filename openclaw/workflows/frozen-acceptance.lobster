name: telemetry-research-frozen-acceptance
args:
  fixture_root:
    default: "tests/fixtures/vertical_slice"
  output_root:
    default: "reports/generated/acceptance"
steps:
  - id: acceptance
    command: >-
      uv run emerging-telemetry-research eval acceptance
      --fixtures "$LOBSTER_ARG_FIXTURE_ROOT"
      --output "$LOBSTER_ARG_OUTPUT_ROOT"
      --json
