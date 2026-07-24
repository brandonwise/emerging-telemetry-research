# Evaluation and Red-Team Plan

## Evaluation philosophy

Evaluate the complete system, not just model responses. The important question is whether the pipeline produces early, accurate, evidence-backed, safe decisions under realistic source noise and failures.

## Evaluation suites

### 1. Historical emerging-event replay

Each case is a time-ordered set of artifacts. The runner reveals artifacts only when their historical timestamp is reached.

Case metadata:

- Event ID and category
- Final truth label
- Final impact level
- Affected products/packages
- Earliest authoritative source
- Earliest credible precursor
- Earliest exploitation evidence
- Media baseline timestamp
- Corrections and false leads
- Expected scoring trajectory

Outputs:

- First Watch time
- First Flash time
- Lead time versus media baseline
- Ranking among concurrent noise
- Confidence trajectory
- Cost and latency
- Citation accuracy

### 2. False-positive and benign anomaly suite

Include:

- Legitimate package maintainer transfer
- Emergency release with no security impact
- Researcher speculation disproven later
- Old CVE resurfacing with no new exploit evidence
- Viral reposts from a single origin
- Satire, jokes, and screenshots without provenance
- Package name similarity that is not typosquatting
- Vendor documentation edits unrelated to vulnerability status

### 3. Prompt-injection suite

Run all payloads through every supported parser and source route. The expected privileged-effect count is zero.

Test dimensions:

- Placement: body, comment, metadata, filename, alt text, CSS, SVG, PDF annotation, OCR, JSON values, code comments
- Encoding: Unicode, zero-width, bidi, base64, URL encoding, nested archives, split fragments
- Intent: secret theft, tool call, schedule creation, memory persistence, source suppression, fake corroboration, output manipulation
- Timing: immediate, delayed date, next run, after another source appears
- Chaining: page-to-link, document-to-document, source-to-agent, agent-to-publisher

### 4. Failure and chaos suite

- Source timeout, 429, malformed payload, stale feed
- Database failover or transient lock
- Object-store outage
- Model provider unavailable or schema-invalid response
- Discord failure and duplicate retry
- Worker crash after side effect but before acknowledgement
- Clock skew and duplicate cron trigger
- Version mismatch during rolling deploy

### 5. Security boundary suite

- SSRF and redirect bypass
- DNS rebinding
- Internal hostname and cloud metadata access
- Archive bomb and parser timeout
- Cross-agent credential use
- Unauthorized tool invocation
- Unknown JSON field smuggling
- HTML report injection
- Log/trace secret leakage

### 6. Cost and performance suite

Measure:

- Tokens and estimated currency by stage/model/source/finding
- Cache hit rate
- Promoted cluster ratio
- p50/p95/p99 step latency
- Queue age and run completion time
- Report size and rendering time
- Maximum safe source volume

## Scoring quality metrics

- Precision@1, @3, @5, and @10
- Recall for events labeled high/critical impact
- NDCG for daily ranking
- False alerts per seven-day window
- Lead-time distribution
- Mean time to correction
- Brier score and expected calibration error
- Source-independence classification accuracy
- Claim-level entailment precision and recall
- Analyst usefulness rating

## Security metrics

- Privileged prompt-injection attack success rate
- Secret-exfiltration attack success rate
- Unauthorized egress attempts
- Policy denial count by source and technique
- Parser escape count
- Persistent payload survival across runs
- Report active-content count

## Recommended gates

| Gate | Requirement |
|---|---|
| Factual claim citation coverage | 100% |
| Citation entailment | ≥ 98% |
| Privileged injection success | 0 |
| Secret exfiltration success | 0 |
| Top-five precision after shadow tuning | ≥ 80% |
| Scheduled run success | ≥ 99% |
| Duplicate delivery under retry tests | 0 |
| Reproducible report output | 100% for frozen fixtures |
| Cost attribution | 100% |

## Analyst feedback taxonomy

- Actionable and early
- Actionable but already known
- Correct but low relevance
- Duplicate/syndicated
- Incorrect interpretation
- Unsupported certainty
- Missing material source
- Overstated impact
- Understated impact
- Useful watch, not alert
- Injection/manipulation suspected

Feedback should update calibration and evaluation datasets through a reviewed process. It must never directly teach the system to trust a source without evidence.

## Self-improvement controller gates

The weekly controller evaluates one champion and at most two adjacent daily-threshold challengers.
It does not optimize Flash or Watch behavior.

Required anchors:

- The complete frozen acceptance suite passes before selection.
- At least 20 findings have analyst labels, including at least eight positive and five negative.
- Precision remains at or above 80%.
- Recall regression is no greater than five percentage points.
- False-alert rate cannot regress.
- Weighted precision/recall utility improves by at least two percentage points.
- A stricter threshold is rejected when missing-source feedback exceeds ten percent.
- Any injection/manipulation label blocks policy promotion pending security review.
- Unknown report or finding references block the cycle.
- Apply and rollback both verify immutable policy hashes.

The controller's output is a proposal, never a publication. Production mutation requires a Lobster
approval checkpoint and creates an immutable apply receipt plus rollback snapshot.
