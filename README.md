# Emerging Telemetry Research

An AI-native emerging telemetry research workflow that turns a clearly described objective into a
bounded collection plan, deterministic scorecard, adversarial review graph, and verified report.
It runs with OpenClaw, Claude Code, Codex, Perplexity, any OpenAI-compatible API, or a plain
scheduler.

Cyber-threat early warning is the original mission pack, not a hardcoded product boundary. The
same engine can research developer-product opportunities, customer pain, market changes,
operational risks, leads, or another outcome while preserving the same source approval, hostile
content, evidence, citation, ranking, and publication controls.

An approved deployment can use surface-tagged Brave searches across the open web, security
research sites, GitHub, Reddit, and TikTok, plus xAI server-side X Search. It looks for pre-CVE
supply-chain, malicious-package, campaign, identity, cloud, vendor, and AI/LLM activity. When
identifiers exist, it corroborates CVEs with CISA KEV, CVE List V5, NVD, FIRST EPSS, OSV, and
GitHub Global Security Advisories. It captures evidence in
PostgreSQL and an
object-locked, versioned S3-compatible store; sanitizes hostile content; normalizes entities; builds
source lineage; scores deterministically; produces verified report JSON and self-contained HTML;
and publishes the results to its durable database and private read-only website.

The built-in scheduler is disabled until an operator activates and schedules a hash-bound mission.
It uses durable leases, bounded retries, and the same workflow regardless of AI harness. Browser
automation is not part of source collection; it is used only for report-rendering QA.

The engine itself is vendor-neutral. It can run with portable SQLite/local object storage or the
production PostgreSQL/S3 profile. Agent platforms remain thin orchestration surfaces; they do not
own evidence, workflow state, analytics, or report history.

## Five-minute local start

Requires Python 3.12–3.14 and `uv`. The recommended path is an authenticated setup page available
only from the local computer. It creates a private ignored workspace; collection, schedules,
delivery, and self-mutation stay off until their own explicit approvals.

```bash
git clone <private-repository-url> emerging-telemetry-research
cd emerging-telemetry-research
uv sync --frozen
uv run emerging-telemetry-research onboard
```

The command opens a one-time loopback link. Choose any installed OpenClaw, Codex, Claude, or
OpenAI-compatible harness; store credentials in the OS keyring; describe the research objective;
review and approve the exact collection boundary; paste extra sites, pages, or RSS feeds; inspect
the compiled plan; and activate it. Shadow/active users can run the cost-acknowledged five-role
harness certification from the same page. No YAML editing is required. Advanced operators can use
the equivalent commands below.

Review `.emerging-telemetry-research/config/`, then bind an approval to the exact code, policies, source terms,
and enabled local sources:

```bash
uv run emerging-telemetry-research setup approval-request --environment-id workstation --json
uv run emerging-telemetry-research setup approval-apply \
  .emerging-telemetry-research/deployment-approval-request.json \
  --approved-by "Your name" \
  --approval-id "change-or-ticket-id" \
  --json
uv run emerging-telemetry-research --env-file .emerging-telemetry-research/config.env \
  setup doctor --profile portable --json
```

Run fixture mode before any network collection:

```bash
uv run emerging-telemetry-research mission run \
  missions/developer-product-opportunities/mission.yaml \
  --signals missions/developer-product-opportunities/fixture-signals.json \
  --output reports/missions \
  --json
make check
make package-smoke
```

See [setup and operation](docs/SETUP.md) and the
[production readiness runbook](docs/PRODUCTION.md) before enabling live collection.

The [production architecture](docs/production-architecture.html) shows the as-built onboarding,
approval, harness, scheduling, evidence, review, publication, and portal boundaries. The
[mission engine](docs/mission-engine.html) shows how a plain-language objective becomes a bounded,
replayable workflow.

Describe a new research objective:

```bash
uv run emerging-telemetry-research mission create \
  --objective "Find recurring developer workflow pain that could support a useful product next quarter." \
  --result-type opportunity \
  --template balanced \
  --json
```

Add an approved source without editing YAML:

```bash
uv run emerging-telemetry-research mission source-add missions/my-research/mission.yaml \
  --url https://engineering.example.com --kind search --json
uv run emerging-telemetry-research mission source-add missions/my-research/mission.updated.yaml \
  --url https://engineering.example.com/feed.xml --kind rss --json
```

`search` constrains discovery to a site, `page` safely fetches one approved HTTPS page, and `rss`
parses a same-site RSS/Atom feed. Direct fetching uses pinned validated IPs, bounded response sizes,
strict content types, disposable time/memory/CPU-bounded parser processes, sanitizer controls, and
no browser or script execution.

Preview the generated source and review plan, then prove it without network access:

```bash
uv run emerging-telemetry-research mission plan \
  missions/developer-product-opportunities/mission.yaml \
  --json

uv run emerging-telemetry-research mission run \
  missions/developer-product-opportunities/mission.yaml \
  --signals missions/developer-product-opportunities/fixture-signals.json \
  --output reports/missions \
  --json
```

Open `/missions/new` in the portal for the guided builder and downloadable mission draft. Live
collection stays off until an operator reviews and activates the compiled source plan. See
[Research missions](docs/MISSIONS.md) covers validation, activation, evaluation, and rollback.

Generate one complete fixture report:

```bash
uv run emerging-telemetry-research fixture run \
  tests/fixtures/vertical_slice/flash-manifest.json \
  --output /tmp/research-flash \
  --json
```

Run the zero-infrastructure portable profile:

```bash
uv run emerging-telemetry-research --env-file .emerging-telemetry-research/config.env \
  portable run --output reports/generated --json
```

This writes immutable evidence objects to `state/objects`, verified reports to
`reports/generated`, trend/report telemetry to `state/research.db`, and a file-only delivery plan. It
never sends externally.

Run the approved live pipeline locally:

```bash
scripts/run-live.sh
```

The script loads Brave, xAI, PostgreSQL, and MinIO credentials from macOS Keychain, verifies
FileVault, starts the loopback-only data services when needed, applies immutable migrations and
bucket retention, writes one verified report to PostgreSQL and the analytics index, and emits a
file-only audit plan. Scheduled runs do not send Discord messages.

Set `ETR_EMAIL_RECIPIENT` on the production run to emit a fixed-recipient email plan. Sending is
a separate operator-approved step: `emerging-telemetry-research report email-send` requires both external-delivery
gates, TLS-protected SMTP, a plan that matches the configured recipient, verified report artifacts,
and an idempotency receipt. SMTP credentials come from the process secret store and never enter a
report or delivery plan. See `docs/SETUP.md` for the variables and command.

Live output reports `source_native_signal_count`, `qualified_emerging_count`, and
`emerging_signal_count`. Every Brave query also keeps its surface ID, so GitHub, Reddit, TikTok,
general web research, and X no longer collapse into one vague bucket. `make eval-coverage` measures
surface count, X share, largest-source concentration, attribution, and whether every finding has
non-X evidence. The five-item brief reserves two slots for qualifying source-native findings.
Generic explainers and evergreen guidance are filtered before source-native promotion so a freshly
indexed tutorial cannot masquerade as an emerging event.

An explicitly configured local profile can send bounded sanitized signal text to an installed
`nomic-embed-text:latest` model through loopback-only Ollama. It runs as a shadow observer: semantic
candidate pairs, deterministic overlap, latency, and token volume are recorded in the immutable
report and analytics index, but embeddings cannot change clusters, scores, verification, or
publication. Ollama failure does not interrupt the deterministic research.

## Analytics and reports

Every live run is indexed into a portable SQLite analytics store. It captures report snapshots,
finding severity and class, source health, provider/model/stage usage and API-equivalent cost
estimates, analyst feedback, improvement-cycle outcomes, and bounded content-free telemetry
events. Cost estimates are attribution signals, not necessarily cash spend: subscriptions, credits,
or committed plans can make incremental cost lower or effectively zero.
Re-index existing immutable reports at any time:

```bash
uv run emerging-telemetry-research analytics sync --json
uv run emerging-telemetry-research analytics overview --days 90 --json
uv run emerging-telemetry-research analytics events --days 90 --json
```

The index is derived and rebuildable; immutable evidence and report JSON remain the source of truth.

## Read-only portal

Start on loopback:

```bash
scripts/run-portal.sh
```

On the production OpenClaw macOS host, install the persistent Keychain-backed private-LAN service:

```bash
scripts/install-portal-service.sh
scripts/portal-status.sh
```

LAN mode binds `0.0.0.0` but accepts only configured private networks and requires a 20+ character
access token by default. Trusted-network deployments can explicitly use
`scripts/install-portal-service.sh --auth disabled`; re-enable it with `--auth required`. Use
`--certfile` and `--keyfile` for TLS; otherwise use only a trusted LAN or an encrypted overlay such
as Tailscale. The portal is read-only and includes a guided research-mission builder, mission and
report views, a filterable security findings archive, categories and tags, a score-sorted analyst
queue, claim verification, deduplicated new-finding and source metrics,
live review posture, deterministic score breakdowns, source-native excerpts and links,
taxonomy trends, report search/detail, source health, provider/model/workflow cost analysis,
print styling, and finding/report CSV/JSON/HTML exports.
The LaunchAgent starts at login, restarts after failure, and retrieves its token from macOS
Keychain without writing it to the plist or logs.

## Platform onboarding

Choose one first-class adapter and generate it into a project checkout:

```bash
uv run emerging-telemetry-research setup generate --platform codex --json
```

Replace `codex` with `openclaw`, `claude-code`, `perplexity`, or `generic` for another adapter.

The Claude Code adapter creates `CLAUDE.md` plus a project skill; the Codex adapter creates
`AGENTS.md` plus a repository skill; OpenClaw receives a Lobster workflow; Perplexity uses the
OpenAI-compatible HTTPS boundary; generic deployments get a shell/cron path. All call the same
CLI, keep secrets outside prompt context, and leave external delivery as a separate approval
boundary.

These adapter shapes follow the official
[Claude Code project configuration and skills model](https://code.claude.com/docs/en/features-overview)
and the official Codex repository-guidance, skills, and non-interactive execution model documented
in the [Codex developer documentation](https://developers.openai.com/codex).

The internal API is available with:

```bash
uv run uvicorn apps.api.main:app --host 127.0.0.1 --port 8080
```

It fails closed unless PostgreSQL, a trusted mTLS proxy IP, and a certificate-fingerprint-to-role
map are configured. The proxy must terminate and verify mutual TLS, strip inbound identity headers,
and inject `X-Client-Cert-SHA256`; callers cannot self-assert that header over an exposed route.

## What is enforced

- External content is data, never instructions.
- Raw source content cannot reach the chief coordinator.
- Collectors cannot send messages, access schedules, or receive delivery credentials.
- Publishers cannot browse and can send only through a fixed-destination OpenClaw tool.
- Cross-agent/model payloads reject unknown fields and non-JSON wrappers.
- Report claims require stored evidence IDs and deterministic verification.
- Reposts and syndication collapse into one originating source chain.
- Fetching enforces HTTPS allowlists, global-address checks, redirect/DNS revalidation, rate limits,
  MIME and size limits, sensitive-header stripping, timeouts, and content hashing.
- Content processing strips active/hidden markup, detects visible/encoded/delayed injection,
  constrains archives, exposes a malware-scanner hook, and gates model access by risk.
- PostgreSQL work claiming uses `SKIP LOCKED`; API commands and delivery plans are idempotent.
- Raw, sanitized, evidence, report, policy, and security records are append-only where required.
- Local Nomic embeddings are loopback-only, bounded, vector-validated, and shadow-only; vectors are
  never persisted and have no publication authority.
- Bounded agents have no tools, memory, collection credentials, delivery credentials, or
  publication authority.
- `plan` records routes without calls; `shadow` executes and records reviews; `active` may add
  bounded narrative analysis while deterministic publication gates stay final.
- Specialist, impact, and skeptic roles run in parallel, then fan into citation verification and a
  coordinator. A failed layer stops downstream dispatch.
- Every workflow node has bounded retries, durable hash-bound checkpoints, and explicit terminal
  states; repeated-state and iteration limits stop runaway loops.
- Collector and agent-provider extensions load only from explicit entry-point allowlists.
- Self-improvement is measurement- and proposal-first; applying any change is a separately
  approved capability and protected security boundaries are never eligible for automatic change.
- Agent evals persist every returned assessment plus role completion, claim-level citation
  coverage, per-role disposition agreement, latency, tokens, cost, and fixture stability.
- CI actions and service images are version pinned; CI runs schema, lint, type, test, PostgreSQL,
  replay, security, and frozen acceptance gates.
- OpenTelemetry exposes bounded, content-free workflow/source/model/delivery/security metrics.

## Architecture

[Watch the animated architecture](docs/architecture-motion.html) for the guided end-to-end runtime,
[open the complete visual architecture](docs/architecture-visual.html) for the ten-diagram as-built
system map, [inspect the mission engine](docs/mission-engine.html) for the objective-to-workflow
lifecycle, and [inspect the universal runtime diagram](docs/universal-agent-runtime.html) for the
provider-neutral agent and source boundaries.

```text
X · Reddit · TikTok · GitHub · web · official sources
  → centralized safe fetch
  → immutable quarantine
  → content-security gateway
  → schema-bound observations
  → entity + source-lineage graph
  → deterministic scoring
  → bounded specialist + impact + skeptic
  → citation verifier → coordinator
  → deterministic publication gate
  → verified report JSON
  → PostgreSQL + analytics index → deterministic HTML + private portal
```

The role-specific specialist, impact, skeptic, verifier, and coordinator are live behind one
provider-neutral runtime. OpenClaw, Codex, Claude, and OpenAI-compatible adapters all consume the
same sanitized packet and return the same strict assessment contract. The deterministic pipeline,
not the coordinator, owns publication.

OpenClaw cron and reviewed Lobster workflows can own orchestration, but Claude Code, Codex, shell,
cron, launchd, systemd, and CI can invoke the same CLI. PostgreSQL or SQLite owns durable state.
Conversation history owns neither.

## Grounded self-improvement

The runtime can measure immutable reports and append-only analyst feedback across source coverage,
calibration, source reliability, provider routing, prompt quality, cost, and security telemetry.
It emits immutable proposal-only advice. A separate champion/challenger graph can evaluate bounded
threshold changes against frozen acceptance anchors.

It cannot change Flash or Watch thresholds, confirmation rules, source terms, content security,
egress, or the fixed Discord destination. It never publishes a report. Approved changes are
hash-checked, limited to one five-point daily-threshold step, and ship with an immutable rollback
snapshot and receipt.

Record one analyst label:

```bash
uv run emerging-telemetry-research feedback record \
  reports/generated/<run-id>/<report-id>.json \
  <finding-id> \
  actionable_and_early \
  --submitted-by operator \
  --json
```

Run one proposal-only cycle:

```bash
uv run emerging-telemetry-research improve advise --json
uv run emerging-telemetry-research improve analyze \
  --reports reports/generated \
  --feedback reports/feedback \
  --output reports/generated/improvement \
  --json
```

Run the reviewed workflow through the OpenClaw Lobster tool with this payload:

```json
{
  "action": "run",
  "pipeline": "openclaw/workflows/self-improvement.lobster",
  "cwd": "workspace/emerging-telemetry-research"
}
```

The workflow currently stops with `insufficient_evidence` until at least 20 grounded labels,
including positive and negative outcomes, exist. The weekly schedule is intentionally disabled
until that feedback corpus is real.

## Production boundary

Read [BLOCKERS.md](BLOCKERS.md), [the production runbook](docs/PRODUCTION.md), and the
[approval template](THREAT_MODEL_APPROVAL.md). The repository grants no operational authority.
Every deployment creates a local, expiring approval bound to its exact protected content, source
set, environment, and capability bits. Browser collection, arbitrary web execution, authenticated
vendor portals, malware detonation, organization inventory, and autonomous defensive action remain
out of scope.

Direct Reddit OAuth and TikTok Research API adapters are included but stay fail-closed until their
platform approval, source-policy record, and credentials exist. Their default surface coverage
comes through Brave search and is tagged separately in telemetry.

## Documentation

- `docs/index.html` — visual architecture and implementation guide
- `docs/sample-daily-brief.html` — report design sample
- `reports/samples/frozen-flash/` — generated report, immutable inputs, and audit log
- `docs/MILESTONE_ACCEPTANCE.md` — design notes, acceptance evidence, and remaining gates
- `ARCHITECTURE.md`, `SECURITY.md`, `THREAT_MODEL.md`, `EVALS.md` — controlling specifications
- `RUNBOOK.md` — operations, incident, replay, restore, and rollback procedures
- `openapi/openapi.yaml` — versioned internal service contract
- `docs/adr/` — architecture decisions and security deviations
- `docs/adr/0008-grounded-self-improvement-graph.md` — loop, graph, approval, and rollback design
- `docs/PORTABILITY.md` — portable profiles and platform onboarding
- `docs/SETUP.md` — install, configure, run, evaluate, and promote
- `docs/EXTENDING.md` — add a source, provider, role, or platform safely
- `docs/PORTAL.md` — local/private-LAN portal operations and security
- `docs/PRODUCTION.md` — production promotion, secrets, operation, backup, restore, and releases
- `docs/architecture-visual.html` — standalone end-to-end visual architecture
- `docs/universal-agent-runtime.html` — standalone source and provider-neutral runtime diagram
- `docs/adr/0009-portable-analytics-and-portal.md` — storage and portal decision record
