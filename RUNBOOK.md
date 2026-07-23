# Operations Runbook

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

## Backup and restore

- Daily database backup and point-in-time recovery where available
- Object-store versioning and retention policy
- Weekly automated restore test into an isolated environment
- Verify that a frozen report can be replayed from restored evidence
- Protect backups with independent credentials and access logging
