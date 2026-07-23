# ADR 0004: Deterministic-first model routing

Status: accepted

## Decision

Use code for collection, parsing, normalization, lineage, scoring, validation, and rendering.
Economical models may perform schema-bound extraction. Balanced models review promoted clusters.
`openai/gpt-5.6-sol` through the Codex harness is reserved for final adjudication and material
disagreement, with no fallback.

## Why

Model judgment is useful at ambiguity boundaries, not as workflow state or a security control.

## Consequences

- Model output is untrusted JSON and must pass a closed schema.
- A coordinator outage holds Flash publication and permits only degraded, deterministic Watch
  output.
- Runtime model availability must be verified before deployment.
