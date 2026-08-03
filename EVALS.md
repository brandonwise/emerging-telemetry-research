# Evaluation and Red-Team Plan

## Evaluation philosophy

Evaluate the complete system, not just model responses. The important question is whether the pipeline produces early, accurate, evidence-backed, safe decisions under realistic source noise and failures.

## Evaluation suites

### Implemented local suites

Run the complete set with:

```bash
make eval-all
```

The current executable suites are:

- `threat-radar eval acceptance`: frozen Flash, Watch, archive, false-positive, and hostile-content
  cases with byte-stable replay checks.
- `threat-radar eval agents`: repeats the five-role DAG over historical fixtures. It records every
  role response under `reviews/`, hashes the artifact, and measures role completion, assessment
  claim presence, claim-level citation coverage, per-role and coordinator agreement, latency,
  input/output tokens, estimated cost, and fixture reproducibility.
- `threat-radar eval coverage`: inspects immutable reports for source attribution, surface count,
  largest-source concentration, X share, non-X evidence, and findings backed only by X.
- `scripts/verify_restore.py`: restores immutable state and compares replayed output.

Source-native promotion rejects generic explainers, tutorials, and evergreen guidance that match a
broad query but do not describe a concrete event. A regression test preserves the false positive
that exposed this gap. Another regression links verbose pre-CVE product coverage back to its
known-CVE cluster so the same event cannot consume two report slots.

Use the deterministic fixture adapter in CI:

```bash
make eval-agents AGENT_ADAPTER=fixture AGENT_REPEATS=3
```

Use a real provider before promotion:

```bash
make eval-agents AGENT_ADAPTER=openclaw AGENT_REPEATS=1
```

The default agent gates require five of five roles, at least one claim in every assessment, a
citation on every factual claim, at least 80% coordinator agreement, no publication authority,
mean review latency no greater than 300 seconds, and mean token use no greater than 100,000 tokens.
Fixture repeats must also be identical after volatile IDs and timestamps are removed.

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

### 7. Source diversity suite

Measure surface diversity separately from raw result volume. Ten reposts from one origin are still
one signal family.

- Distinct source IDs and source types
- Largest-source evidence share
- X evidence share
- Non-X evidence count
- Unattributed evidence count
- Findings with no non-X support
- Source health and request counts, including zero-result surfaces

The default gate requires at least four surfaces, no single source above 60% of cited evidence, X
at or below 50%, full attribution, and non-X evidence on every finding.

### 8. Outcome mission suite

Each mission declares its useful-outcome rate and source-diversity floor. Run its checked-in signal
fixture in plan mode, then use `threat-radar mission evaluate` on the immutable report. The built-in
developer-product mission proves that the engine can produce a cited, code-ranked non-security
outcome from three source types.

Mission gates cover:

- valid mission, signal, report, and feedback contracts;
- fixed five-role dependencies and mission-specific role briefs;
- source registration, surface matching, independent hosts, and maximum evidence age;
- citation coverage and code-owned ranking;
- source diversity and useful-outcome rate;
- tamper-evident activation and exact rollback;
- zero live collection authority in plan mode;
- immutable useful, not useful, and needs-work feedback.

Before analyst feedback exists, evaluation labels usefulness as a `priority_proxy`. Once feedback
exists for the report, it switches to `analyst_feedback` and uses the latest label per outcome.
Neither path can change source approval or score weights automatically.

## Evaluation loop

1. Run the frozen acceptance suite.
2. Run the agent suite with the fixture adapter to catch contract and orchestration regressions.
3. Run one real-provider case and inspect the full role artifacts, not only the aggregate result.
4. Run a live collection in `plan` or `shadow` mode.
5. Run source coverage against that exact report set.
6. Change one prompt, route, threshold, or source query.
7. Repeat the same cases and compare quality, latency, tokens, and source concentration.
8. Promote to `active` only when the deterministic anchors still pass.

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
| Mission claims cited | 100% |
| Mission source registration and age enforcement | 100% |

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
