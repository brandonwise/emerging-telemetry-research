# Remaining deployment gates

The repository is production-engineered but intentionally grants no live authority. A target
environment must complete its own local approval and operational evidence before collection:

- Create and review a hash-bound deployment approval for the exact enabled source set; tracked
  files and another machine's approval are not sufficient.
- Validate provider executables/endpoints and run real-provider shadow evals.
- Configure a real malware-scanner hook; the development no-op hook is not a release posture.
- Complete PostgreSQL point-in-time and object-lock restore drills plus alert-delivery testing.
- Put the internal API behind a deployed mTLS-terminating proxy before any non-loopback exposure.
- Enable schedules only in the deployment layer after `setup doctor` reports ready.

These items require separate scope approvals:

- Authenticated vendor portals, Reddit, OpenSSF malicious-package feeds, precursor collectors,
  certificate-transparency monitoring, and media-baseline retention remain disabled until their
  terms and source-specific controls are approved.
- The internal API remains loopback-only. Exposing it requires a deployed mTLS-terminating proxy;
  only that proxy may inject `X-Client-Cert-SHA256`, and its source IP must be configured in
  `ETR_API_TRUSTED_PROXY_IPS_JSON`.
- Flash-class autonomous delivery remains disabled pending the shadow-evaluation window in
  `EVALS.md`.
- Organization inventory, automated defensive action, browser-based collection, malware
  detonation, Tor, and arbitrary web execution require separate threat models.
