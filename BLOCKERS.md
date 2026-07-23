# Release blockers

These items intentionally block live collection and external delivery. They are not implementation
shortcuts.

- Threat model approval is pending in `THREAT_MODEL_APPROVAL.md`.
- Legal and source-terms review is pending for every source in `config/source-terms.yaml`.
- Production object-store versioning, retention lock, encryption keys, and restore evidence are not
  configured.
- The internal API needs a deployed mTLS-terminating proxy. Only that proxy may inject
  `X-Client-Cert-SHA256`, and its source IP must be configured in
  `RADAR_API_TRUSTED_PROXY_IPS_JSON`.
- Discord bot credentials, a private destination, and an immutable approval reference are not
  configured.
- Shadow-mode evaluation has not accumulated the release-window evidence defined in `EVALS.md`.
- Production backup/restore, dead-letter replay, rollback, and OpenClaw deep-audit evidence must be
  captured in the release review.

No source, schedule, or external-delivery flag may be enabled while any applicable item remains
open.
