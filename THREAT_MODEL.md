# Threat Model

## Protected assets

- Model-provider, source, GitHub, database, object-store, Discord, and email credentials
- Internal infrastructure and network reachability
- Organization asset/dependency inventory
- Analyst identities and private feedback
- Source acquisition methods and watchlists
- Raw artifacts and potentially sensitive indicators
- Evidence integrity and provenance
- Report integrity, confidentiality, and delivery correctness
- Workflow configuration, schedules, prompts, policies, and model routing
- Cost budgets and service availability

## Adversaries

- Threat actor planting prompt injections in pages, repositories, package metadata, comments, documents, or social posts
- Malicious package maintainer or compromised upstream account
- Sybil network manufacturing apparent corroboration
- Source site serving targeted or delayed content
- Compromised third-party API, model provider, browser, extension, dependency, or CI action
- Insider or operator with excessive privileges
- Opportunistic attacker targeting exposed services or secrets
- Benign but erroneous sources producing harmful false positives

## Entry points

- HTTP responses and redirects
- HTML, JSON, XML, RSS/Atom, PDFs, Office documents, archives, images, and metadata
- Git commits, issue text, release notes, package manifests, install scripts, and binary assets
- Social posts, replies, links, profile fields, and media captions
- API responses and webhooks
- Model output
- Cross-agent messages
- Configuration pull requests and CI workflows
- Discord/email rendering and link handling

## Major abuse cases

### TM-01: Source content instructs an agent to reveal secrets

**Impact:** credential theft, data exposure.

**Controls:** no secrets in research contexts, content as data, egress restrictions, canary detection, output schema, publisher isolation.

### TM-02: Source content induces a privileged tool call

**Impact:** message delivery, schedule creation, file modification, or command execution.

**Controls:** collector/publisher separation, no privileged tools for analysts, semantic action gateway, unknown-field rejection, deterministic orchestration.

### TM-03: Hidden or encoded injection bypasses sanitizer

**Impact:** manipulation of extraction or assessment.

**Controls:** canonicalization, hidden-text detection, bounded excerpts, second-pass classifier, skeptic/verifier, no privileged authority even after bypass.

### TM-04: SSRF reaches internal services or cloud metadata

**Impact:** credential theft or internal compromise.

**Controls:** centralized fetch, IP denial, DNS/redirect revalidation, egress network isolation, no arbitrary browser destination.

### TM-05: Malicious artifact exploits a parser

**Impact:** worker compromise.

**Controls:** disposable sandbox, resource limits, patching, no host mounts, no secrets, quarantine, content-type restrictions.

### TM-06: Syndicated or coordinated posts inflate confidence

**Impact:** false Flash alert or manipulation.

**Controls:** source-lineage graph, origin attribution, account/source diversity, historical reliability, skeptic review.

### TM-07: Fabricated citation or unsupported model claim

**Impact:** misleading report and loss of trust.

**Controls:** evidence IDs selected from allowed packet, claim/evidence verifier, deterministic URI/timestamp resolution, 100% citation coverage gate.

### TM-08: Time-bomb payload persists across runs

**Impact:** delayed unauthorized behavior.

**Controls:** no source-derived memory or schedules, typed durable state, template versioning, expiring hypotheses, re-sanitization.

### TM-09: Runaway agents or model loops cause excessive cost

**Impact:** budget exhaustion or denial of service.

**Controls:** step limits, tool-loop detection, per-run/model/source budgets, circuit breakers, early exits, operator approval for emergency budget.

### TM-10: Compromised connector or source credential

**Impact:** forged evidence, terms violation, data exposure.

**Controls:** credential isolation, source-specific identity, anomaly detection, rotation, signed authoritative feeds where available, provenance and replay.

### TM-11: Compromised CI dependency/action changes policies

**Impact:** supply-chain compromise of the radar itself.

**Controls:** pinned actions, protected branches, CODEOWNERS, reviews, SBOM, dependency scanning, signed/attested artifacts, minimal workflow permissions.

### TM-12: Report renderer includes active hostile content

**Impact:** analyst browser compromise or tracking.

**Controls:** render escaped text only, no source HTML, CSP, no remote scripts/images by default, safe link redirect page, attachment scanning.

### TM-13: False attribution harms a person or organization

**Impact:** reputational and legal risk.

**Controls:** no attribution without strong evidence, separate observation/inference, confidence language, corrections, review threshold.

### TM-14: Organization inventory leaks through model/provider

**Impact:** exposure of defensive posture.

**Controls:** minimize data, local relevance matching where feasible, provider policy review, pseudonymous asset identifiers, no inventory in collector prompts.

### TM-15: Local embedding output creates false semantic relationships

**Impact:** unrelated source reports are merged, inflating confidence or hiding a critical signal.

**Controls:** fixed loopback endpoint, bounded sanitized input, numeric-only validated output,
taxonomy compatibility, no vector persistence, shadow-only telemetry, and no path from embedding
output to clustering, scoring, verification, or publication. Local-inference failures leave the
deterministic pipeline unchanged.

## Trust-boundary acceptance tests

- A collector token cannot authenticate to delivery services.
- A delivery token cannot read raw artifacts.
- Coordinator containers cannot resolve or route to the public internet.
- Sanitizer containers have no persistent writable host mount.
- A model-supplied unknown action is rejected.
- A URL resolving to a public IP and redirecting to a private IP is rejected.
- A report renders source text as escaped text with a restrictive content-security policy.
- A source instruction cannot survive as a schedule, memory item, or policy.
- Local embedding output cannot alter a cluster, score, claim, or publication decision.
