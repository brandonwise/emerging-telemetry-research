# Setup and operation

## 1. Install

```bash
git clone <repository-url>
cd openclaw-emerging-threat-radar
make setup
make validate
```

`make help` lists every supported workflow and its overrides.

## 2. Configure discovery

Copy `.env.example` into your secret-management workflow. At minimum, provide:

```dotenv
BRAVE_API_KEY=
XAI_API_KEY=
```

Brave covers separately tagged web, security-research, GitHub, Reddit, and TikTok surfaces. xAI
provides curated X Search. Direct Reddit OAuth and TikTok Research API collection are optional and
disabled by default.

For approved direct platform access:

```dotenv
REDDIT_ACCESS_TOKEN=
REDDIT_USER_AGENT=
TIKTOK_RESEARCH_ACCESS_TOKEN=
```

Then set the matching `enabled` flag in `config/discovery.yaml`, change its source-terms record
from `pending` to `approved`, and add the approval ID to `config/sources.yaml`. TikTok requires an
approved Research API project with `research.data.basic`; its client access token expires after
two hours, so refresh it in the host secret workflow rather than inside an agent prompt.

Review before changing a source:

- `config/discovery.yaml`: queries, communities, limits, and promotion caps
- `config/sources.yaml`: source registry and enabled state
- `config/source-terms.yaml`: approval and retention record
- `THREAT_MODEL_APPROVAL.md`: approved environment and boundaries

## 3. Choose an agent runtime

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

Valid adapters are `fixture`, `openclaw`, `codex`, `claude`, and `openai-compatible`. See
`docs/PORTABILITY.md` for provider-specific environment variables.

## 4. Run

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

## 5. Evaluate before activation

```bash
make acceptance
make eval-agents AGENT_ADAPTER=fixture AGENT_REPEATS=3
make eval-agents AGENT_ADAPTER=openclaw AGENT_REPEATS=1
make eval-coverage
```

Inspect the real-provider aggregate and every JSON file under its `reviews/` directory. Check
disagreements, unsupported certainty, latency, tokens, and follow-up requests—not just the pass
boolean.

## 6. Verify the repository

```bash
make check
make build
```

`make check` runs contract validation, lint, type checking, tests, all eval suites, and the restore
drill. The report template and architecture diagrams also require local browser QA before release.

## 7. Promote

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

## 8. Roll back

Set `RADAR_AGENT_MODE=plan` to stop agent calls without changing evidence or reports. Disable one
source in `config/sources.yaml` and `config/discovery.yaml` to isolate collection. Never delete old
evidence or rewrite an immutable report; publish a corrected version.
