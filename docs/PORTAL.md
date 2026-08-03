# Emerging Telemetry Research portal

The portal is a read-only operational view over `state/research.db` and immutable reports. It uses
server-rendered HTML, local CSS, semantic controls, responsive layouts, accessible focus states,
print styling, and no third-party browser assets or JavaScript.

## Loopback mode

```bash
scripts/run-portal.sh
```

Open <http://127.0.0.1:8088>. Loopback mode rejects non-loopback clients. Authentication is
optional because the operating-system boundary already restricts access.

## Private-LAN mode

For this OpenClaw host, install the persistent Keychain-backed LaunchAgent:

```bash
scripts/install-portal-service.sh
scripts/portal-status.sh
```

The service starts at login, restarts after failure, stores no token in its plist or environment,
and writes logs under `~/.openclaw/logs`. Remove it without deleting analytics or the access token:

```bash
scripts/uninstall-portal-service.sh
```

Add `--purge-token` only when the Keychain token should also be deleted.

Token authentication is the private-LAN default. On a trusted internal network, it can be
explicitly disabled:

```bash
scripts/install-portal-service.sh --auth disabled
```

The portal remains read-only and private-CIDR filtered. The Keychain token is preserved so
authentication can be restored with `scripts/install-portal-service.sh --auth required`.

For an interactive foreground process instead:

```bash
export ETR_PORTAL_ACCESS_TOKEN="$(openssl rand -hex 24)"
scripts/run-portal.sh --lan --port 8088
```

The script prints the private network URL. LAN mode:

- binds the server to `0.0.0.0`
- accepts clients only from configured private CIDRs
- requires a 20+ character access token by default
- permits explicit trusted-network mode with `--auth disabled` or `--no-auth`
- converts the token to an HMAC-signed, 12-hour, HttpOnly, SameSite=Strict session cookie
- does not trust proxy forwarding headers
- exposes no write, collection, scheduling, or delivery routes

For encrypted transport, provide both:

```bash
scripts/run-portal.sh --lan \
  --certfile /path/to/cert.pem \
  --keyfile /path/to/key.pem
```

TLS enables secure cookies. Without TLS, use only a trusted LAN or an encrypted overlay network.
Do not forward the portal port from a router or expose it to the public internet.
Disabled authentication is appropriate only when every allowed client and network segment is
trusted. Re-enable authentication before port forwarding, using a guest network, or widening the
CIDR allowlist.

## Capabilities

- guided plain-language mission builder with an exact source/query preview
- downloadable plan-mode mission YAML; collection remains disabled until CLI approval
- mission inventory, activation posture, evidence rules, role briefs, and verified research reports
- score-sorted analyst queue bounded to the selected time window
- deduplicated priority, claim verification, new-finding, source-health, and publication-mix KPIs
- attributed evidence mix with distinct source and evidence counts, X share, and non-X volume
- live agent-review completion, failure, and blocked-role counts from operational reports
- claim-verification counts derived from indexed immutable reports
- Settings-page provider/model and workflow-stage cost attribution with subscription-plan context
- latest local Nomic semantic-shadow health, recall candidates, deterministic overlap, and latency
- finding-level search and filters for category, tag, and discovery source type
- source-native website and X-post excerpts with original links and timestamps
- category and tag trend summaries
- daily publication trends across configurable windows
- workflow, feedback, and self-improvement event summaries
- report search and edition filters
- verified report detail, deterministic score anatomy, claim ledger, and defensive checks
- bounded agent-review status and role chain when a report contains review artifacts
- latest source-health snapshots
- immersive animated runtime architecture with a reduced-motion control
- linked ten-view blueprint covering trust, agents, routing, storage, deployment, and activation
- CSV and JSON archive exports
- finding-level CSV and JSON exports with tags and discovery-source types
- per-report JSON and deterministic HTML exports
- responsive and print layouts

## Metric contract

Dashboard and trend metrics use only reports that contain persisted `discovery_telemetry` from a
live collection run. Frozen fixtures, acceptance runs, benchmark artifacts, and older reports that
cannot prove live provenance remain indexed for audit purposes but are excluded from operational
totals.

- Findings are keyed by `finding_id`. The overview counts each ID once, and posture metrics use the
  newest state in the selected window.
- "New findings" means the first operational report for that ID falls inside the selected window.
  "Seen before" means the ID existed in operational telemetry before that window.
- Daily trends count a recurring finding at most once per day, using its newest state that day.
- Evidence counts use distinct cited evidence IDs from the newest finding states. Source counts use
  distinct source IDs; source type is a separate grouping.
- Source health is the most recent persisted collection result for each source, not an average of
  historical attempts.
- Claim verification is the share of cited claims whose persisted verification status is
  `verified`. Evidence confidence is a deterministic evidence-strength label, not a calibrated
  probability that the threat will materialize.
- Agent-review completion comes from live report review artifacts. Fixture evaluation results do
  not appear as operational health.
- Request and token volume are measured from persisted usage records. Currency is an
  API-equivalent estimate and is not presented as actual cash spend.

The portal does not publish an early-warning lead KPI until an approved, independently collected
media baseline exists. Generic discovery timestamps are never treated as a media baseline.

CSV cells beginning with spreadsheet formula characters are escaped. Report HTML exports resolve
only indexed immutable files whose filename matches the requested report ID.

## Recovery

If the analytics database is lost, rebuild it:

```bash
uv run emerging-telemetry-research analytics sync \
  --reports reports/generated \
  --database state/research.db \
  --json
```

This rebuilds derived analytics only. It does not modify reports or raw evidence.
