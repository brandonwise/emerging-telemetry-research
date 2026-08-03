# Setup and operation

## 1. Install

```bash
git clone <repository-url>
cd outcome-radar
uv sync --frozen --extra dev
make validate
uv run outcome-radar setup init --profile portable --json
```

Python 3.12–3.14 is supported on Linux, macOS, and Windows. `setup init` creates an ignored,
owner-only `.outcome-radar/` workspace containing editable config, state, and report paths. It
never changes the tracked fail-closed defaults. `make help` lists every supported workflow.

## 2. Configure secrets

Use the OS credential store for an interactive workstation:

```bash
uv run outcome-radar setup secret-set BRAVE_API_KEY
uv run outcome-radar setup secret-set XAI_API_KEY
```

The local config receives only `keyring://` references. CI, containers, and orchestrators can use
`env://NAME` or an absolute `file:///run/secrets/name` reference. File secrets reject symlinks,
oversized/non-UTF-8 content, and non-owner permissions on POSIX. Never put a secret value in a
mission, prompt, report, approval, generated adapter, or committed env file.

## 3. Review and approve collection

Brave covers separately tagged web, security-research, GitHub, Reddit, and TikTok surfaces. xAI
provides curated X Search. Direct Reddit OAuth and TikTok Research API collection are optional.
Review these local files before granting collection:

- `.outcome-radar/config/discovery.yaml`: queries, communities, limits, and promotion caps
- `.outcome-radar/config/sources.yaml`: enabled source registry
- `.outcome-radar/config/source-terms.yaml`: legal approval and retention record
- `.outcome-radar/config/scoring.yaml`: deterministic ranking policy
- `.outcome-radar/config/models.yaml`: routing, retries, token ceilings, and budgets

Generate a request bound to the current code, policy, schemas, source plan, and terms; then apply it
only after review:

```bash
uv run outcome-radar setup approval-request --environment-id workstation --json
uv run outcome-radar setup approval-apply \
  .outcome-radar/deployment-approval-request.json \
  --approved-by "Operator name" \
  --approval-id "ticket-or-change-id" \
  --expires-days 30 \
  --json
uv run outcome-radar --env-file .outcome-radar/config.env \
  setup doctor --profile portable --json
```

Copying another machine's approval does not grant authority: protected-content drift, a changed
source set, capability mismatch, or expiration fails closed. The tracked
`THREAT_MODEL_APPROVAL.md` is a template, not an approval.

For approved direct platform access:

```dotenv
REDDIT_ACCESS_TOKEN=
REDDIT_USER_AGENT=
TIKTOK_RESEARCH_ACCESS_TOKEN=
```

Then set the matching `enabled` flag in the local discovery config and approve its local source
terms before generating a new deployment approval request. TikTok requires an
approved Research API project with `research.data.basic`; its client access token expires after
two hours, so refresh it in the host secret workflow rather than inside an agent prompt.

### Create an outcome mission

Use the portal mission builder or the CLI before configuring live collection:

```bash
uv run outcome-radar mission create \
  --objective "Find recurring workflow pain that could support a useful product next quarter." \
  --outcome opportunity \
  --json
```

Run `mission validate` and `mission plan`, then test with fixture signals. A draft stays in plan
mode. Live collection requires `mission activate` with a named approver and approval ID; activation
writes a hash-checked rollback receipt. Full commands and contract boundaries are in
`docs/MISSIONS.md`.

## 4. Choose an agent runtime

No model calls:

```dotenv
RADAR_AGENT_MODE=plan
```

Run reviews without applying them:

```dotenv
RADAR_AGENT_MODE=shadow
RADAR_AGENT_ADAPTER=openclaw
```

Apply bounded review narrative:

```dotenv
RADAR_AGENT_MODE=active
RADAR_AGENT_ADAPTER=openclaw
```

Valid built-ins are `auto`, `fixture`, `openclaw`, `codex`, `claude`, and `openai-compatible`.
`auto` follows every configured preference with bounded retries and circuit breaking. Third-party
providers load only through the `outcome_radar.agent_providers` entry-point group and an explicit
`RADAR_AGENT_PLUGIN_ALLOWLIST`. See `docs/PORTABILITY.md` for provider configuration.

## 5. Run

Zero-infrastructure local state:

```bash
make portable
```

Production stores:

```bash
make stack-up
make live
```

The default output root is `reports/generated`. External delivery stays disabled.

### Email delivery

Email uses a fixed-recipient SMTP adapter. The report plan stores a SHA-256 recipient identifier,
not the mailbox address. The sender recomputes that identifier from its secret-backed environment
and refuses a mismatch. SMTP must use implicit TLS or STARTTLS.

Set the non-secret connection values and load the password from your platform secret store:

```dotenv
RADAR_EMAIL_RECIPIENT=security@example.com
RADAR_EMAIL_SENDER=threat-radar@example.com
RADAR_SMTP_HOST=smtp.example.com
RADAR_SMTP_PORT=587
RADAR_SMTP_SECURITY=starttls
RADAR_SMTP_USERNAME=threat-radar@example.com
RADAR_SMTP_PASSWORD=
```

`RADAR_EMAIL_RECIPIENT` makes `outcome-radar live run` emit an email delivery plan instead of a
file-only plan. It does not send anything. After an operator reviews the report and plan, enable
both gates for the delivery process and send that exact plan:

```bash
export EXTERNAL_DELIVERY_ENABLED=true
export RADAR_EMAIL_DELIVERY_ENABLED=true
uv run outcome-radar report email-send \
  reports/generated/<run-id>/<report-id>.delivery.json \
  --report-root reports/generated
```

The sender verifies every claim, constrains the HTML attachment to the report root, checks the
fixed recipient, and writes an idempotency receipt before connecting. A retry after a confirmed
delivery returns the existing receipt. A retry after an unknown outcome stops rather than risking
a duplicate email.

## 6. Evaluate before activation

```bash
make acceptance
make eval-agents AGENT_ADAPTER=fixture AGENT_REPEATS=3
make eval-agents AGENT_ADAPTER=openclaw AGENT_REPEATS=1
make eval-coverage
```

Inspect the real-provider aggregate and every JSON file under its `reviews/` directory. Check
disagreements, unsupported certainty, latency, tokens, and follow-up requests—not just the pass
boolean.

## 7. Verify the repository

```bash
make check
make package-smoke
```

`make check` runs contract validation, lint, type checking, tests, all eval suites, and the restore
drill. The report template and architecture diagrams also require local browser QA before release.

## 8. Promote

Use `shadow` until:

- frozen acceptance passes;
- five of five roles complete;
- every assessment includes claims and every factual claim cites evidence;
- coordinator agreement meets the eval threshold;
- source concentration passes;
- latency and tokens are inside the configured limits;
- the full returned assessments have been reviewed.

Switch to `active` for narrative enrichment only. Deterministic scoring and publication remain
authoritative.

## 9. Self-improvement and rollback

Generate proposal-only recommendations across coverage, calibration, source reliability, routing,
prompt quality, cost, and security telemetry:

```bash
uv run outcome-radar improve advise --json
```

Advice is immutable and never applies itself. `improve apply` additionally requires an unexpired
deployment approval with the `self_improvement_apply` capability. Credentials, approval rules,
delivery boundaries, security policy, and executable tools are protected from automatic change.

Set `RADAR_AGENT_MODE=plan` to stop agent calls without changing evidence or reports. Disable one
source in the local source and discovery config, generate a new approval, and remove the old local
approval to isolate collection. Never delete old evidence or rewrite an immutable report; publish
a corrected version.

For an activated outcome mission, run `outcome-radar mission rollback` with its activation receipt.
This restores the exact pre-activation contract and verifies its base hash before writing it.

See `docs/PRODUCTION.md` for deployment, backup, restore, release, and incident-response gates.
