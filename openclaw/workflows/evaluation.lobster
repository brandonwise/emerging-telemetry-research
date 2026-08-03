name: threat-radar-evaluation
args:
  suite:
    default: "weekly-production-retrospective"
  agent_adapter:
    default: "fixture"
  agent_repeats:
    default: "3"
steps:
  - id: acceptance
    command: >-
      uv run outcome-radar eval acceptance
      --fixtures tests/fixtures/vertical_slice
      --output reports/generated/evaluation
      --json

  - id: bounded_agent_evaluation
    command: >-
      uv run outcome-radar eval agents
      --fixtures tests/fixtures/vertical_slice
      --adapter "$LOBSTER_ARG_AGENT_ADAPTER"
      --repeats "$LOBSTER_ARG_AGENT_REPEATS"
      --output reports/generated/agent-evaluation
      --json

  - id: source_coverage_evaluation
    command: >-
      uv run outcome-radar eval coverage
      --reports reports/generated
      --output reports/generated/source-evaluation
      --minimum-surfaces 4
      --maximum-surface-share 0.60
      --maximum-x-share 0.50
      --json
