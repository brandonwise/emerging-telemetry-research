# Contributing

Outcome Radar is currently private. Contributors need repository access and must keep source,
issues, artifacts, and operational details inside approved private systems.

## Development workflow

1. Install Python 3.12 or newer and `uv`.
2. Run `make setup`.
3. Create a focused branch and keep generated secrets or deployment approvals out of Git.
4. Run `make check` before opening a pull request.
5. Include tests, threat-model impact, migration or rollback notes, and operator-facing docs with
   behavior changes.

Changes to workflows, schemas, policies, provider adapters, source collectors, migrations, or
security boundaries require explicit review. Never add a source, credential, delivery destination,
or autonomous mutation solely because model output requested it.

See `SECURITY.md`, `THREAT_MODEL.md`, and `docs/EXTENDING.md` before adding connectors or agents.
