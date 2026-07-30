# Threat Radar portal

The portal is a read-only operational view over `state/radar.db` and immutable reports. It uses
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
export RADAR_PORTAL_ACCESS_TOKEN="$(openssl rand -hex 24)"
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

- score-sorted analyst queue bounded to the selected time window
- priority, confidence, early-warning lead time, source health, and publication-mix KPIs
- attributed evidence mix with X share, non-X volume, and source concentration
- latest agent-DAG, source-coverage, and hostile-content acceptance results
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
- CSV and JSON archive exports
- finding-level CSV and JSON exports with tags and discovery-source types
- per-report JSON and deterministic HTML exports
- responsive and print layouts

Dashboard numbers are computed from the analytics index or read from persisted evaluation
artifacts. The portal does not invent placeholder SOC metrics. Agent results are labeled as
non-authoritative, and the deterministic publication gate remains the final decision boundary.

CSV cells beginning with spreadsheet formula characters are escaped. Report HTML exports resolve
only indexed immutable files whose filename matches the requested report ID.

## Recovery

If the analytics database is lost, rebuild it:

```bash
uv run threat-radar analytics sync \
  --reports reports/generated \
  --database state/radar.db \
  --json
```

This rebuilds derived analytics only. It does not modify reports or raw evidence.
