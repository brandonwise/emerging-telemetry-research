name: threat-radar-evaluation
args:
  suite:
    default: "weekly-production-retrospective"
steps:
  - id: acceptance
    command: >-
      uv run threat-radar eval acceptance
      --fixtures tests/fixtures/vertical_slice
      --output reports/generated/evaluation
      --json
