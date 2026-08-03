# ADR 0011: Local semantic clustering in shadow mode

Status: accepted

## Context

The deterministic complete-link title matcher is intentionally conservative. That protects
against source-driven mega-clusters and false confidence, but it can miss two reports describing
the same event with different vocabulary. The production Mac already runs Ollama and has
`nomic-embed-text:latest`; using that local model avoids another paid API and keeps discovery text
on the host.

The installed `qwen3:0.6b` generative model is not approved for classification or prioritization.
In a synthetic critical-signal test it mislabeled an actively exploited, unauthenticated,
pre-authentication VPN RCE as medium severity. It remains outside the research decision path.

## Decision

1. Send bounded, sanitized title/summary/rationale text only to the fixed
   `http://127.0.0.1:11434/api/embed` endpoint.
2. Disable proxy inheritance and redirects. Accept only the configured model name and a bounded,
   finite, consistently dimensioned numeric response.
3. Evaluate no more than 64 source-native signals and 1,200 characters per signal per run, with a
   ten-second timeout and four-megabyte response limit.
4. Compare semantic candidate pairs only within compatible deterministic taxonomies.
5. Persist aggregate quality metrics and at most 20 evidence-ID pair references. Never persist
   embedding vectors.
6. Record Ollama request/token usage with an estimated incremental API cost of zero.
7. Keep the integration in `shadow` mode. It cannot mutate clusters, scores, claims, verification,
   report selection, publication class, or delivery.
8. Treat local-inference absence, timeout, or malformed output as a shadow degradation. The
   deterministic research continues unchanged.
9. Display the newest shadow observation under Settings, away from the operational overview.

## Data flow

```text
sanitized discovery signals
  ├─> deterministic complete-link clustering ─> authoritative findings
  └─> bounded text ─> loopback Ollama/Nomic ─> numeric vectors
                                             └─> shadow pair metrics + evidence IDs
                                                  └─> report / analytics / Settings
```

There is no path from the semantic shadow result back into authoritative clustering or
publication.

## Security analysis

- **Spoofing/tampering:** a process impersonating Ollama is confined to loopback. The adapter
  validates the exact requested model, vector count, dimensions, numeric finiteness, and bounds.
  Its output still has no publication authority.
- **Repudiation:** the immutable report records model, threshold, counts, latency, token volume,
  evidence-ID candidates, and explicitly records `publication_authority: false`.
- **Information disclosure:** source excerpts never leave the host through this adapter; proxy
  environment variables are ignored and no credentials are sent.
- **Denial of service:** signal count, text length, timeout, response bytes, vector dimensions, and
  stored candidates are bounded. Failure cannot stop deterministic publication.
- **Elevation of privilege/prompt injection:** the model has no tools and returns numeric vectors
  only. Source instructions cannot become actions, policy, memory, scores, or findings.

## Promotion gate

Shadow mode may be reconsidered only after a reviewed replay set demonstrates a material recall
gain without unacceptable false merges. Any promotion requires a separate threat-model approval,
deterministic guardrails, rollback evidence, and updated acceptance tests.
