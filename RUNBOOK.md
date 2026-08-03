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

The Makefile exposes the same gates with shorter commands:

```bash
make help
make check
make package-smoke
```

Initialize and validate a target deployment:

```bash
uv run outcome-radar setup init --profile production --json
uv run outcome-radar setup approval-request --environment-id production-host --json
# Independently review and apply the request.
uv run outcome-radar --env-file .outcome-radar/config.env \
  setup doctor --profile production --json
```

On macOS, `scripts/run-live.sh` remains a hardened convenience wrapper around the same CLI and
local approval. Linux and Windows deployments should call the CLI with an explicit env file or
their orchestrator's protected environment.

Before live collection, confirm all of the following:

- `.outcome-radar/deployment-approval.yaml` is unexpired, owner-only, and valid for the current
  protected-content hash, capability, and source set.
- Every enabled local source has approved terms in `.outcome-radar/config/source-terms.yaml`.
- `scripts/validate_repo.py` passes after the source/config change.
- Egress allowlists contain only source-specific hostnames.
- The live text-artifact scanner reports `clean`; binary/document collection is not enabled.
- PostgreSQL restore, object-lock restore, OpenClaw deep audit, and alert delivery evidence are
  attached to the production-readiness review.

## Agent operating modes

- `plan`: build and persist routes; make no model calls.
- `shadow`: execute all five roles and persist their assessments; do not apply them to findings.
- `active`: execute all five roles and add bounded narrative analysis. Deterministic scoring and
  publication remain authoritative.

Start with one real-provider fixture:

```bash
uv run outcome-radar eval agents \
  --adapter openclaw \
  --case flash \
  --repeats 1 \
  --output reports/generated/agent-evaluation-openclaw \
  --json
```

Inspect both `agent-eval-results.json` and every file under `reviews/`. A pass requires complete
roles, evidence citations, disposition agreement, bounded latency/tokens, and zero publication
authority. If one layer fails, downstream roles must not run.

Run a live shadow:

```bash
make agent-shadow AGENT_ADAPTER=openclaw
```

Use `agent-active` only after the real-provider eval and frozen acceptance suite both pass.

## Source coverage

The default collector uses separate Brave query IDs for web research, supply chain, campaigns,
AI security, identity/cloud, GitHub, Reddit, and TikTok, plus xAI X Search and authoritative
vulnerability sources. Run:

```bash
make eval-coverage
```

Do not call Reddit's unauthenticated `.json` routes. Direct Reddit collection requires explicit
Reddit Data API approval, an OAuth token, a descriptive user agent, `reddit.enabled: true`, and an
updated source-terms record. TikTok direct Research API collection requires TikTok approval and is
not part of the default profile.

## Daily operator review

- Confirm morning and afternoon runs completed
- Review Flash and Watch changes in the private portal
- Check source freshness and degraded-source banner
- Check model/tool usage and daily budget
- Review policy denials and sanitizer high-risk counts
- Confirm analytics indexing and portal freshness
- Review local semantic-shadow health and potentially missed pairs in Settings
- Triage analyst feedback and corrections

## Local semantic shadow

The optional local shadow model is `nomic-embed-text:latest` through the fixed loopback Ollama
endpoint when that profile is explicitly enabled.
It is an observer, not a fallback decision-maker. Check the Settings page or the
`semantic_shadow` object in the newest report for status, latency, candidate pairs, and overlap
with deterministic clustering.

If status is `degraded`:

1. Confirm `ollama list` includes `nomic-embed-text:latest`.
2. Confirm the loopback service responds; do not change the endpoint to a LAN or public host.
3. Keep the deterministic run. Local-inference failure is not a reason to broaden egress or delay
   verified publication.
4. Re-run the next normal cycle after service recovery. Do not edit an immutable prior report.

Do not promote semantic candidates into authoritative clustering based on anecdotes. Promotion
requires a labeled replay set, a separate threat-model approval, deterministic safety gates, and
rollback evidence.

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

## Portal publication failure

- Confirm the verified report exists in PostgreSQL and `reports/generated`.
- Re-run analytics sync; it is immutable and idempotent.
- Verify the portal service can read `state/radar.db`.
- Do not enable Discord or another external transport as a workaround.
- Alert an operator after the configured retry window.

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

1. Record analyst feedback with `outcome-radar feedback record`; never edit a prior feedback file.
2. Run `outcome-radar improve advise` and `outcome-radar improve analyze` or the reviewed
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
uv run outcome-radar improve rollback \
  reports/generated/improvement/<cycle-id>/apply-receipt.json \
  --repo-root . \
  --approved-by <operator> \
  --approval-id <change-record-id> \
  --json
```

The rollback refuses to run if the active scoring policy changed after apply or if the snapshot hash
does not match the receipt.

## Portal service

The local OpenClaw host runs the read-only portal as a per-user LaunchAgent:

```bash
scripts/install-portal-service.sh
scripts/portal-status.sh
```

The installer creates the portal access token in macOS Keychain if absent, installs
`ai.openclaw.threat-radar-portal`, verifies `/health`, and records a bounded analytics event. It
never prints the token. Service logs are `~/.openclaw/logs/threat-radar-portal*.log`.

Authentication is required by default. For a trusted, private network, reinstall the service with
`scripts/install-portal-service.sh --auth disabled`. The private-CIDR boundary remains active and
the token stays in Keychain. Restore authentication with `--auth required`.

The Findings view separates CVE-backed findings from pre-CVE source-native signals through
categories, tags, and source-type filters. Early signals intentionally preserve the cited source's
language and confidence boundary; `reported` does not mean the underlying event is confirmed.

Rollback is recoverable and preserves data:

```bash
scripts/uninstall-portal-service.sh
```

This boots out the service and moves its plist to Trash. It preserves the token unless
`--purge-token` is explicit. It never deletes `state/radar.db`, reports, evidence, or exports.

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
