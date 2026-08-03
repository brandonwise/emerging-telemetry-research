# Portable deployment

## The durable boundary

`emerging-telemetry-research` owns collection, evidence, scoring, verification, reports, and state. Agent
platforms are replaceable adapters around its CLI and versioned JSON contracts.

```text
X · Reddit · TikTok · GitHub · web · official sources
  → safe acquisition + immutable evidence
  → deterministic correlation and scoring
  → optional bounded-agent review
  → deterministic publication gate
  → verified JSON + self-contained HTML
```

The portable profile uses SQLite and local content-addressed objects. Production can substitute
PostgreSQL and object-locked S3-compatible storage without changing the workflow contract.

## Fast path

Requirements:

- Python 3.12–3.14
- `uv`
- Brave Search API key for the default web surfaces
- xAI API key with X Search access when the X surface is enabled
- one optional agent provider

```bash
uv sync --frozen --extra dev
uv run emerging-telemetry-research setup init --profile portable --json
uv run emerging-telemetry-research setup secret-set BRAVE_API_KEY
uv run emerging-telemetry-research setup secret-set XAI_API_KEY
uv run emerging-telemetry-research setup approval-request --environment-id workstation --json
# Review the request, then apply it with a named operator and change/ticket ID.
uv run emerging-telemetry-research --env-file .emerging-telemetry-research/config.env \
  setup doctor --profile portable --json
```

Portable output:

- `state/research.db`: immutable API records, analytics, trends, source health, and bounded telemetry
- `state/objects`: content-addressed source objects and metadata
- `reports/generated`: verified JSON, self-contained HTML, reviews, evals, and local delivery plans

## Agent modes

- `plan` records the graph and model routes without dispatching a model.
- `shadow` runs the graph and stores reviews without changing findings.
- `active` may add bounded narrative analysis. It cannot change the deterministic publication
  class or publish anything.

All providers receive the same sanitized evidence packet. They get no tools, memory, raw
artifacts, collection secrets, delivery secrets, or publication authority.

## Provider adapters

### OpenClaw

The command adapter dispatches five isolated, tool-free role agents. Register the workspaces from
`openclaw/agents/`, then use:

```bash
make openclaw-agents-check
# After reviewing the scoped changes, if agents are missing:
make openclaw-agents-install
# Restart the OpenClaw gateway only when the installer reports a change.
```

```dotenv
ETR_AGENT_MODE=shadow
ETR_AGENT_ADAPTER=openclaw
```

### Codex

The command adapter runs ephemeral, read-only `codex exec` sessions with the assessment JSON
Schema:

```dotenv
ETR_AGENT_MODE=shadow
ETR_AGENT_ADAPTER=codex
```

### Claude Code

The command adapter disables tools and session persistence and requires structured JSON:

```dotenv
ETR_AGENT_MODE=shadow
ETR_AGENT_ADAPTER=claude
```

### Perplexity or another OpenAI-compatible API

```dotenv
ETR_AGENT_MODE=shadow
ETR_AGENT_ADAPTER=openai-compatible
ETR_AGENT_PROVIDER_NAME=perplexity
ETR_AGENT_BASE_URL=https://api.perplexity.ai
ETR_AGENT_MODEL=your-approved-model
ETR_AGENT_API_KEY_REF=keyring://emerging-telemetry-research/ETR_AGENT_API_KEY
ETR_AGENT_INPUT_PRICE_PER_MILLION=your-current-input-price
ETR_AGENT_OUTPUT_PRICE_PER_MILLION=your-current-output-price
```

Prices are explicit deployment configuration because provider/model pricing changes. They are
used for attribution and the persisted daily-spend baseline. Hard runtime reservations use the
reviewed `maximum_currency_per_call` values in the local model routing config. Before dispatch,
the ledger reserves the full worst-case envelope across every configured fallback and retry, so a
missing price
estimate cannot disable the run and cluster caps.

The HTTP adapter first requests strict JSON Schema output. If an otherwise compatible endpoint
rejects that option with HTTP 400 or 422, it retries without the option and still validates the
returned object locally.

### Deterministic fixture

`ETR_AGENT_ADAPTER=fixture` runs without a model. Use it for CI, contract tests, and stable
workflow replay—not for production analysis.

## Generate platform setup

```bash
uv run emerging-telemetry-research setup generate --platform codex --json
```

Supported values:

- `openclaw`: reviewed Lobster orchestration
- `claude-code`: project `CLAUDE.md` and a Telemetry Research skill
- `codex`: project `AGENTS.md` and a Telemetry Research skill
- `perplexity`: OpenAI-compatible environment and operating guide
- `generic`: shell runner and scheduler-neutral guide

Generation refuses to overwrite files unless `--force` is explicit. Generated instructions check
for secrets without printing them and never grant external delivery.

## Source portability

Brave queries keep independent source IDs for general web research, security research, GitHub,
Reddit, and TikTok. xAI X Search remains a separate source. Official CVE and advisory collectors
are deterministic.

Direct platform APIs are optional:

- Reddit requires Reddit approval and OAuth. Unauthenticated `.json` collection is not supported.
- TikTok requires eligibility, an approved Research API project, the `research.data.basic` scope,
  and a short-lived client access token. The included `tiktok-research` adapter queries public
  video metadata and constructs only canonical `/@user/video/id` evidence URLs.

The default surface-search path therefore works without either platform credential while still
measuring Reddit and TikTok separately. A source adapter must preserve its origin ID even when it
shares a search provider.

To activate either direct adapter, provide its environment variables, set the adapter's
`config/discovery.yaml` flag to `true`, and record approval in both `config/sources.yaml` and
`config/source-terms.yaml`. Missing credentials fail the enabled source as degraded rather than
silently falling back. See the
[Reddit Data API access requirements](https://support.reddithelp.com/hc/en-us/articles/14945211791892-Developer-Platform-Accessing-Reddit-Data),
[TikTok Research API overview](https://developers.tiktok.com/products/research-api/), and
[TikTok Query Videos contract](https://developers.tiktok.com/doc/research-api-specs-query-videos/).

## Scheduling

Any scheduler that can run a command can operate the portable profile:

```bash
./run-research.sh --agent-mode shadow --agent-adapter openai-compatible
```

OpenClaw, cron, systemd, launchd, CI, Codex, and Claude all call the same CLI. Conversation history
is never workflow state.

The generated package includes both POSIX shell and PowerShell runners. Env files are parsed as
data and are never sourced as shell code. Durable SQLite workflow checkpoints make restarts resume
completed nodes only when their input and node-revision hashes still match.

## Delivery

Portable runs produce `destination: file:local`. External notification or ticketing adapters may
consume a verified delivery plan only after destination and credential approval. Collection
credentials never share the delivery boundary.
