name: threat-radar-self-improvement
args:
  reports_root:
    default: "reports/generated"
  feedback_root:
    default: "reports/feedback"
  output_root:
    default: "reports/generated/improvement"
steps:
  - id: analyze
    command: >-
      uv run threat-radar improve analyze
      --reports "$LOBSTER_ARG_REPORTS_ROOT"
      --feedback "$LOBSTER_ARG_FEEDBACK_ROOT"
      --output "$LOBSTER_ARG_OUTPUT_ROOT"
      --fixtures tests/fixtures/vertical_slice
      --scoring-config config/scoring.yaml
      --improvement-config config/improvement.yaml
      --json

  - id: apply_bounded_challenger
    command: >-
      uv run threat-radar improve apply-stdin
      --repo-root .
      --approved-by lobster-human-gate
      --approval-id lobster_weekly_gate
      --json
    stdin: $analyze.stdout
    condition: $analyze.json.status == "approval_required"
    approval: required
