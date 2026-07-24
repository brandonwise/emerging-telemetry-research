# Operations Runbook

## Safety preflight

Run before any deployment or configuration change:

```bash
uv sync --frozen --extra dev
uv run python scripts/validate_repo.py
uv run ruff check .
uv run mypy apps packages scripts/run_acceptance.py scripts/verify_restore.py
uv run pytest
uv run python scripts/run_acceptance.py --output /tmp/radar-acceptance
uv run python scripts/verify_restore.py --output /tmp/radar-restore
```

Stop if a command fails. Do not enable a source, schedule, model fallback, or delivery channel to
work around a failed gate.

For the approved local daily brief, run:

```bash
scripts/run-live.sh
```

The runner loads secrets from macOS Keychain, verifies FileVault, starts the loopback-only
PostgreSQL and MinIO services, and emits delivery metadata as JSON. Send only through the reviewed
OpenClaw `radar_delivery_send` tool; never bypass it with a generic message or Discord client.

Before live collection, confirm all of the following:

- `THREAT_MODEL_APPROVAL.md` contains an immutable approval reference, approver, timestamp, commit,
  source IDs, environment, and residual-risk acceptance.
- Every enabled source has `status: approved` in `config/source-terms.yaml`.
- `scripts/validate_repo.py` passes after the source/config change.
- Egress allowlists contain only source-specific hostnames.
- The malware-scanner hook reports `clean`, not `not_configured`.
- PostgreSQL restore, object-lock restore, OpenClaw deep audit, and alert delivery evidence are
  attached to the production-readiness review.

## Daily operator review

- Confirm morning and afternoon runs completed
- Review Flash alerts and Watch changes
- Check source freshness and degraded-source banner
- Check model/tool usage and daily budget
- Review policy denials and sanitizer high-risk counts
- Review delivery receipts
- Triage analyst feedback and corrections

## Source outage

1. Confirm whether the source is unavailable, rate limited, credential expired, or adapter broken.
2. Do not broaden egress or disable validation as a workaround.
3. Mark source health degraded and continue the run.
4. Use an approved alternate authoritative source if configured.
5. Include the coverage gap in the report.
6. Backfill from the durable cursor after recovery.

## Suspected prompt-injection incident

1. Disable the affected connector route or artifact family.
2. Preserve artifact, sanitizer, model, policy, and tool logs.
3. Verify whether any privileged effect or secret exposure occurred.
4. Revoke affected scoped credentials if uncertainty remains.
5. Identify all clusters/reports derived from the artifact.
6. Publish a correction if report integrity was affected.
7. Add the payload and variants to the injection regression suite.
8. Review and strengthen the trust boundary, not only the detector.

## False Flash alert

1. Freeze the finding and preserve the evidence/version record.
2. Identify whether failure came from source independence, extraction, scoring, reasoning, verification, or policy.
3. Issue a visible correction linked to the original alert.
4. Add the case to historical replay and false-positive suites.
5. Adjust deterministic features or gates through reviewed configuration.
6. Do not merely add a prompt exception.

## Model provider outage

- Route extraction to the configured alternate economical provider
- Route balanced analysis to an approved fallback
- If coordinator is unavailable, publish only deterministic source updates or delay final classification
- Never silently use an unapproved model for organization-sensitive data
- Mark the report degraded and show affected stages

## Budget threshold exceeded

- Stop promotion of low-priority clusters
- Use cached results and deterministic processing only
- Downgrade approved analysis tasks according to model policy
- Preserve Flash candidate budget
- Require operator approval for emergency budget extension
- Include the budget event in telemetry

## Discord delivery failure

- Retry with the same idempotency key
- Avoid generating a new report version for transport retries
- Store the HTTP/provider receipt or error category
- Fall back to the approved email/file channel only when policy allows
- Alert an operator after the configured retry window

## Dead-letter replay

1. Identify the `dead_letter_id`, original run/step, input reference/hash, redacted error, and policy
   revision that will be used for replay.
2. Resolve the cause without changing stored input. If the fix broadens egress, tool rights, source
   terms, or retention, stop for a separate security review.
3. Claim rows through `claim_dead_letters(worker_id, maximum_items)`. Never update arbitrary rows
   directly.
4. Build the replay step from the original input hash and reviewed policy revision. The resulting
   idempotency key must be deterministic.
5. Execute through the normal workflow boundary, not an operator shell shortcut.
6. Mark the dead letter replayed only after the new step is durable. Retain the original record.
7. Verify the report/audit hashes or document the intentional version difference.

## Backup and restore

Production requirements:

- Daily encrypted PostgreSQL backup with point-in-time recovery.
- Object-store versioning, retention policy, and object lock where supported.
- Independent backup credentials and access logging.
- Weekly automated restore into an isolated account/network.

Restore drill:

1. Create an isolated database and object-store bucket with no delivery credentials.
2. Restore PostgreSQL to the selected recovery point.
3. Restore object versions and verify stored content hashes against `raw_artifacts`.
4. Run frozen replay against the restored inputs and the original code/policy/template revisions.
5. Compare report JSON, HTML, and audit bytes.
6. Run referential-integrity checks across evidence, claim, report, usage, and delivery records.
7. Record duration, recovery point, mismatches, and operator identity.
8. Destroy the isolated environment through the approved infrastructure workflow.

The local immutable-evidence drill is:

```bash
uv run python scripts/verify_restore.py --output /tmp/radar-restore
```

It does not replace the production PostgreSQL/object-lock drill.

## Partial report

- Continue when one source fails and remaining evidence can still support every claim.
- Mark the source `degraded` or `failed`, preserve the error category, and show the coverage gap.
- Recompute independence using only available originating chains.
- Never retain a Flash classification that no longer satisfies its deterministic confirmation rule.
- Hold publication when evidence lineage or verification is incomplete.

## Self-improvement cycle

1. Record analyst feedback with `threat-radar feedback record`; never edit a prior feedback file.
2. Run `threat-radar improve analyze` or the reviewed
   `openclaw/workflows/self-improvement.lobster` workflow.
3. If the result is `insufficient_evidence`, collect more labels. Do not lower the sample gates.
4. If the result is `blocked`, resolve the acceptance, orphan-reference, or security-review reason
   before rerunning.
5. If the result is `no_change`, keep the champion. A loop that does nothing is healthier than one
   forced to mutate.
6. If the result is `approval_required`, inspect the champion/challenger precision, recall,
   false-alert rate, immutable anchor hashes, and exact one-field diff.
7. Approve only through the Lobster checkpoint. The apply command verifies the base policy hash and
   writes `apply-receipt.json` plus `rollback/scoring.yaml`.
8. Run the safety preflight and one shadow report before relying on the new daily threshold.

Rollback an applied proposal:

```bash
uv run threat-radar improve rollback \
  reports/generated/improvement/<cycle-id>/apply-receipt.json \
  --repo-root . \
  --approved-by <operator> \
  --approval-id <change-record-id> \
  --json
```

The rollback refuses to run if the active scoring policy changed after apply or if the snapshot hash
does not match the receipt.

## Rollback

1. Disable schedules and external delivery first; do not delete evidence.
2. Pin the last approved code, policy, schema, and template revisions.
3. Drain or dead-letter claimed work; preserve idempotency keys.
4. Roll back application services. Apply a database rollback only if a reviewed forward-compatible
   migration is impossible.
5. Replay one frozen fixture and one restored production run in shadow mode.
6. Re-enable collection by approved source class, then schedules, then delivery.
7. Record the rollback decision, approver, hashes, affected runs, and residual risk.

## Internal API identity failure

- Confirm the request arrived only from the configured mTLS proxy IP.
- Confirm the proxy verified the client certificate and stripped caller-supplied identity headers.
- Compare the injected SHA-256 fingerprint with the configured role map.
- Return 401 for an untrusted proxy/certificate, 403 for a valid identity with the wrong role, and
  503 when the identity map or durable repository is unavailable.
- Never make the API externally reachable to repair identity propagation.
