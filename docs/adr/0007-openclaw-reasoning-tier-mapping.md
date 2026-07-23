# ADR 0007: OpenClaw `max` maps to the chief's ultra-high reasoning tier

Status: accepted

## Context

The model routing policy names the chief tier `ultra`. OpenClaw 2026.7.1-2 exposes `max` as its
highest agent reasoning enum.

## Decision

Keep `ultra` in the provider-neutral model policy and configure the chief OpenClaw agent with
`thinkingDefault: "max"`. The chief remains pinned to `openai/gpt-5.6-sol` with no fallback.

## Consequences

- Deployment validation must confirm the mapping whenever OpenClaw is upgraded.
- A newly available higher tier requires a reviewed configuration change.
- The current runtime reports `openai/gpt-5.6-sol` as available.
