# Outcome missions

A mission is a reviewable contract for one research outcome. It says what to find, where the
system may look, what counts as enough evidence, how results are scored, which review roles should
challenge them, and what a useful run looks like.

Security is one mission pack. The same engine can research developer-product opportunities,
customer pain, market changes, operational risks, leads, or another bounded outcome without
giving a prompt permission to write or run a scraper.

## Start with the decision

Use the portal at `/missions/new`, or create a draft from the CLI:

```bash
uv run emerging-telemetry-research mission create \
  --objective "Find recurring developer workflow pain that could support a useful product next quarter." \
  --outcome opportunity \
  --name "Developer Product Opportunity Research" \
  --window-hours 336 \
  --cadence weekly \
  --json
```

A useful objective names:

- the result you want, such as an opportunity, risk, trend, lead, or change;
- the person or decision the research should support;
- the timing, evidence, or action constraint that makes the result useful.

The compiler extracts bounded keywords, drafts approved source adapters, creates a deterministic
scorecard, and applies the proven five-role challenge graph. It does not execute collection.

## Review the plan

```bash
uv run emerging-telemetry-research mission validate missions/my-mission/mission.yaml --json
uv run emerging-telemetry-research mission plan missions/my-mission/mission.yaml --json
```

The plan shows every query, source surface, result limit, evidence rule, score dimension, role
brief, and output limit. Unsupported template fields, duplicate IDs, weights that do not total 100,
or a changed review graph fail validation.

## Prove it with fixture evidence

Plan-mode missions can run against a checked-in signal set without network access:

```bash
uv run emerging-telemetry-research mission run \
  missions/developer-product-opportunities/mission.yaml \
  --signals missions/developer-product-opportunities/fixture-signals.json \
  --output reports/missions \
  --json
```

The run sanitizes source text, rejects unsafe URLs and prompt-injection patterns, deduplicates and
clusters signals, enforces independent-source minimums, scores in code, plans or executes bounded
reviews, validates every claim citation, and writes immutable JSON, HTML, and a run manifest.
External delivery remains disabled.

Evaluate the result against the mission's own success gates:

```bash
uv run emerging-telemetry-research mission evaluate \
  missions/developer-product-opportunities/mission.yaml \
  --report reports/missions/<mission-id>/<report-id>/report.json \
  --json
```

Record whether an outcome was genuinely useful. Feedback is stored as an immutable event and the
latest label for each outcome replaces the priority proxy in usefulness evaluation:

```bash
uv run emerging-telemetry-research mission feedback \
  missions/developer-product-opportunities/mission.yaml \
  --report reports/missions/<mission-id>/<report-id>/report.json \
  --outcome-id <outcome-id> \
  --label useful \
  --reason "This supports a concrete product discovery interview." \
  --submitted-by "Product owner" \
  --json
```

Valid labels are `useful`, `not_useful`, and `needs_work`. Feedback informs evaluation; it never
silently rewrites source approval, score weights, or collection policy.

## Activate live collection

Activation is a deliberate approval, not a button hidden inside onboarding:

```bash
uv run emerging-telemetry-research mission activate \
  missions/my-mission/mission.yaml \
  --approved-by "Research owner" \
  --approval-id "change-1234" \
  --json
```

This writes `mission.active.yaml` and `activation-receipt.json`. The activated mission includes the
base hash, a tamper-evident approved-content hash, and an approval reference on every enabled
source. Any edit after approval invalidates the seal. Only that contract may run with
`--live`:

```bash
export BRAVE_API_KEY="from-your-secret-store"
uv run emerging-telemetry-research mission run missions/my-mission/mission.active.yaml --live --json
```

Restore the exact pre-activation draft with its hash-checked receipt:

```bash
uv run emerging-telemetry-research mission rollback activation-receipt.json \
  --output mission.rolled-back.yaml \
  --json
```

## What remains fixed

Mission authors can change objectives, vocabulary, approved sources, queries, evidence floors,
score dimensions, role briefs, cadence, output limits, and evaluation targets. They cannot remove
citation requirements, enable external delivery, bypass source approval, grant agents tools, move
ranking into a model, or give a role publication authority.

The role graph stays fixed:

```text
specialist ─┐
impact ─────┼─→ citation verifier → coordinator → deterministic gate
skeptic ────┘
```

The engine owns safety and provenance. The mission owns the outcome.
