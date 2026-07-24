# Portable deployment

## Contract

The durable boundary is the `threat-radar` CLI plus versioned JSON schemas. OpenClaw, Claude Code,
Codex, and generic schedulers are adapters. No adapter owns evidence, report history, scoring,
verification, or self-improvement state.

```text
Brave + xAI + official sources
  → portable threat-radar CLI
  → immutable local objects + SQLite
  → verified JSON + deterministic HTML
  → file-only delivery plan
  → optional approved platform delivery adapter
```

The production profile substitutes PostgreSQL and object-locked S3-compatible storage while using
the same discovery, content security, normalization, scoring, verification, and reporting code.

## Fast path

Requirements:

- Python 3.12
- `uv`
- Brave Search API key
- xAI API key with X Search access

```bash
uv sync --extra dev --python 3.12
export BRAVE_API_KEY="..."
export XAI_API_KEY="..."
uv run threat-radar portable run --json
```

Portable output:

- `state/radar.db`: immutable API records, report analytics, trends, source health, and bounded
  telemetry events
- `state/objects`: content-addressed immutable source objects and metadata
- `reports/generated`: verified report JSON, self-contained HTML, audit records, and a local
  delivery plan

`state/radar.db` is operational state and should be backed up, but the analytics portion can be
rebuilt from reports with `threat-radar analytics sync`.

## Platform adapters

Generate one adapter from a repository checkout:

```bash
uv run threat-radar setup generate --platform generic --json
```

Supported values:

- `openclaw`: reviewed Lobster orchestration, with delivery still isolated behind an approved tool
- `claude-code`: project `CLAUDE.md` and `.claude/skills/threat-radar/SKILL.md`
- `codex`: project `AGENTS.md` and `.agents/skills/threat-radar/SKILL.md`
- `generic`: shell runner and a scheduler-neutral operating guide

Existing files are never overwritten unless `--force` is explicit. Generated instructions verify
secret presence without printing secret values. They do not grant external delivery.

Claude Code officially supports project `CLAUDE.md`, settings, project skills, subagents, hooks, and
MCP configuration. Codex supports repository `AGENTS.md`, repository skills, project configuration,
non-interactive `codex exec`, and MCP. The project uses only the smallest portable subset: durable
instructions and a CLI boundary. Hooks and MCP can be added without changing the core workflow.

Official references:

- <https://code.claude.com/docs/en/features-overview>
- <https://code.claude.com/docs/en/claude-directory>
- <https://code.claude.com/docs/en/cli-usage>
- <https://developers.openai.com/codex>

## Delivery

Portable runs produce `destination: file:local`. That is intentional. Email, Discord, Slack,
ticketing, and other delivery adapters consume a verified delivery plan only after destination and
credential approval. Collection credentials never share a process boundary with delivery
credentials.
