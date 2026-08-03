name: threat-radar-self-improvement
args:
  reports_root:
    default: "reports/generated"
  feedback_root:
    default: "reports/feedback"
  mission_feedback_root:
    default: "reports/mission-feedback"
  output_root:
    default: "reports/generated/improvement"
steps:
  - id: advise
    command: >-
      uv run outcome-radar improve advise
      --reports "$LOBSTER_ARG_REPORTS_ROOT"
      --feedback "$LOBSTER_ARG_FEEDBACK_ROOT"
      --mission-feedback "$LOBSTER_ARG_MISSION_FEEDBACK_ROOT"
      --output "${LOBSTER_ARG_OUTPUT_ROOT}-advice"
      --improvement-config config/improvement.yaml
      --json

  - id: analyze
    command: >-
      uv run outcome-radar improve analyze
      --reports "$LOBSTER_ARG_REPORTS_ROOT"
      --feedback "$LOBSTER_ARG_FEEDBACK_ROOT"
      --output "$LOBSTER_ARG_OUTPUT_ROOT"
      --fixtures tests/fixtures/vertical_slice
      --scoring-config config/scoring.yaml
      --improvement-config config/improvement.yaml
      --json

  - id: apply_bounded_challenger
    command: >-
      uv run outcome-radar improve apply-stdin
      --repo-root .
      --approved-by lobster-human-gate
      --approval-id lobster_weekly_gate
      --json
    stdin: $analyze.stdout
    condition: $analyze.json.status == "approval_required"
    approval: required
