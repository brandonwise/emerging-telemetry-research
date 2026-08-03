# Setup and operation

## 1. Install

```bash
git clone <repository-url>
cd emerging-telemetry-research
uv sync --frozen --extra dev
make validate
uv run emerging-telemetry-research setup init --profile portable --json
```

Python 3.12–3.14 is supported on Linux, macOS, and Windows. `setup init` creates an ignored,
owner-only `.emerging-telemetry-research/` workspace containing editable config, state, and report paths. It
never changes the tracked fail-closed defaults. `make help` lists every supported workflow.

For a non-technical local setup, replace the last two commands with:

```bash
uv sync --frozen
uv run emerging-telemetry-research onboard
```

The local control plane uses a fresh one-time token, a one-hour HttpOnly strict session cookie,
CSRF protection, loopback client and Host checks, restrictive browser policy, and no secret
rendering. It also shows the protected control hash and base source list before collecting a
hash-bound approval; external delivery and self-improvement remain disabled. Stop it with Ctrl+C
when setup is complete.

## 2. Configure secrets

Use the OS credential store for an interactive workstation:

```bash
uv run emerging-telemetry-research setup secret-set BRAVE_API_KEY
uv run emerging-telemetry-research setup secret-set XAI_API_KEY
```

The local config receives only `keyring://` references. CI, containers, and orchestrators can use
`env://NAME` or an absolute `file:///run/secrets/name` reference. File secrets reject symlinks,
oversized/non-UTF-8 content, and non-owner permissions on POSIX. Never put a secret value in a
mission, prompt, report, approval, generated adapter, or committed env file.

## 3. Review and approve collection

Brave covers separately tagged web, security-research, GitHub, Reddit, and TikTok surfaces. xAI
provides curated X Search. Direct Reddit OAuth and TikTok Research API collection are optional.
Review these local files before granting collection:

- `.emerging-telemetry-research/config/discovery.yaml`: queries, communities, limits, and promotion caps
- `.emerging-telemetry-research/config/sources.yaml`: enabled source registry
- `.emerging-telemetry-research/config/source-terms.yaml`: legal approval and retention record
- `.emerging-telemetry-research/config/scoring.yaml`: deterministic ranking policy
- `.emerging-telemetry-research/config/models.yaml`: routing, retries, token ceilings, and budgets

Generate a request bound to the current code, policy, schemas, source plan, and terms; then apply it
only after review:

```bash
uv run emerging-telemetry-research setup approval-request --environment-id workstation --json
uv run emerging-telemetry-research setup approval-apply \
  .emerging-telemetry-research/deployment-approval-request.json \
  --approved-by "Operator name" \
  --approval-id "ticket-or-change-id" \
  --expires-days 30 \
  --json
uv run emerging-telemetry-research --env-file .emerging-telemetry-research/config.env \
  setup doctor --profile portable --json
```

The onboarding control plane performs these same request/apply steps only after the local operator
expands the protected-source preview and provides an approver identity and approval reference.

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

### Create a research mission

Use the portal mission builder or the CLI before configuring live collection:

```bash
uv run emerging-telemetry-research mission create \
  --objective "Find recurring workflow pain that could support a useful product next quarter." \
  --result-type opportunity \
  --json
```

Run `mission validate` and `mission plan`, then test with fixture signals. A draft stays in plan
mode. Live collection requires `mission activate` with a named approver and approval ID; activation
writes a hash-checked rollback receipt. Full commands and contract boundaries are in
`docs/MISSIONS.md`.

## 4. Choose an agent runtime

No model calls:

```dotenv
ETR_AGENT_MODE=plan
```

Run reviews without applying them:

```dotenv
ETR_AGENT_MODE=shadow
ETR_AGENT_ADAPTER=openclaw
```

Apply bounded review narrative:

```dotenv
ETR_AGENT_MODE=active
ETR_AGENT_ADAPTER=openclaw
```

Valid built-ins are `auto`, `fixture`, `openclaw`, `codex`, `claude`, and `openai-compatible`.
`auto` follows every configured preference with bounded retries and circuit breaking. Third-party
providers load only through the `emerging_telemetry_research.agent_providers` entry-point group and an explicit
`ETR_AGENT_PLUGIN_ALLOWLIST`. See `docs/PORTABILITY.md` for provider configuration.

Discover harnesses without spending provider quota, then certify the selected harness before
shadow or active use:

```bash
uv run emerging-telemetry-research setup harnesses --json
uv run emerging-telemetry-research setup harness-test \
  --adapter codex --acknowledge-cost --json
```

Certification executes the complete five-role structured-output graph and writes a 30-day receipt
bound to the harness version, executable, endpoint, and model. Changing those values invalidates
the receipt. Command adapters use their existing authenticated session; compatible HTTP endpoints
use only the configured secret reference. The onboarding control plane exposes the same test with
an explicit provider-quota acknowledgement, so it does not require terminal work.

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

Schedule an activated mission portably on Windows, macOS, or Linux:

```bash
uv run emerging-telemetry-research schedule add \
  .emerging-telemetry-research/missions/<mission-id>/mission.active.yaml --run-now --json
uv run emerging-telemetry-research schedule serve
```

The durable SQLite scheduler claims due runs with leases, prevents concurrent duplicate claims,
retries a failed run after five minutes, and preserves the last bounded error. Its worker still
requires the deployment collection approval, so a schedule cannot bypass governance.

### Email delivery

Email uses a fixed-recipient SMTP adapter. The report plan stores a SHA-256 recipient identifier,
not the mailbox address. The sender recomputes that identifier from its secret-backed environment
and refuses a mismatch. SMTP must use implicit TLS or STARTTLS.

Set the non-secret connection values and load the password from your platform secret store:

```dotenv
ETR_EMAIL_RECIPIENT=security@example.com
ETR_EMAIL_SENDER=telemetry-research@example.com
ETR_SMTP_HOST=smtp.example.com
ETR_SMTP_PORT=587
ETR_SMTP_SECURITY=starttls
ETR_SMTP_USERNAME=telemetry-research@example.com
ETR_SMTP_PASSWORD=
```

`ETR_EMAIL_RECIPIENT` makes `emerging-telemetry-research live run` emit an email delivery plan instead of a
file-only plan. It does not send anything. After an operator reviews the report and plan, enable
both gates for the delivery process and send that exact plan:

```bash
export EXTERNAL_DELIVERY_ENABLED=true
export ETR_EMAIL_DELIVERY_ENABLED=true
uv run emerging-telemetry-research report email-send \
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
uv run emerging-telemetry-research improve advise --json
```

Advice is immutable and never applies itself. `improve apply` additionally requires an unexpired
deployment approval with the `self_improvement_apply` capability. Credentials, approval rules,
delivery boundaries, security policy, and executable tools are protected from automatic change.

Set `ETR_AGENT_MODE=plan` to stop agent calls without changing evidence or reports. Disable one
source in the local source and discovery config, generate a new approval, and remove the old local
approval to isolate collection. Never delete old evidence or rewrite an immutable report; publish
a corrected version.

For an activated research mission, run `emerging-telemetry-research mission rollback` with its activation receipt.
This restores the exact pre-activation contract and verifies its base hash before writing it.

See `docs/PRODUCTION.md` for deployment, backup, restore, release, and incident-response gates.
