# Remaining scope gates

The approved local daily brief is live. These items block expansion beyond that reviewed boundary:

- Authenticated vendor portals, Reddit, OpenSSF malicious-package feeds, precursor collectors,
  certificate-transparency monitoring, and media-baseline retention remain disabled until their
  terms and source-specific controls are approved.
- The internal API remains loopback-only. Exposing it requires a deployed mTLS-terminating proxy;
  only that proxy may inject `X-Client-Cert-SHA256`, and its source IP must be configured in
  `RADAR_API_TRUSTED_PROXY_IPS_JSON`.
- Flash-class autonomous delivery remains disabled pending the shadow-evaluation window in
  `EVALS.md`.
- Organization inventory, automated defensive action, browser-based collection, malware
  detonation, Tor, and arbitrary web execution require separate threat models.
- Off-host disaster recovery and point-in-time restore remain operational follow-ups; local
  PostgreSQL volumes and MinIO object locking protect the current deployment.

These gates do not block the approved daily 7:30 AM ET Brave + X + authoritative-source brief.
