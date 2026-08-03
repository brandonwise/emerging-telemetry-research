# ADR 0008: Grounded self-improvement graph

Status: accepted

## Context

The production research needs to improve from analyst outcomes without allowing an optimizer to weaken
the evidence, security, source-terms, egress, or delivery controls that define a trustworthy result.
A single optimizing loop is vulnerable to metric gaming, stale labels, blind threshold changes, and
self-review.

## Decision

Run a slower, separate improvement graph around the daily production graph:

```text
immutable policy snapshot
  ├─→ analyst feedback + production reports ─→ champion evaluation
  │                                      ├─→ lower-threshold challenger ─┐
  │                                      └─→ higher-threshold challenger ├─→ selection
  └─→ frozen acceptance and security gates ──────────────────────────────┘
                                                                          │
                                              no change ← fail gates ─────┤
                                              human approval ← pass ──────┘
                                                                          │
                                                      apply + rollback receipt
```

Each weekly run is one loop iteration. The graph makes fan-out, fan-in, state, and routing explicit.
Champion and challenger metrics are computed independently from immutable report scores and the
latest append-only analyst label for each finding.

The initial learnable surface is deliberately narrow: `thresholds.daily` may move by at most five
points per approved cycle and must remain between 40 and 60. Flash and Watch thresholds, hard
confirmation rules, source terms, content security, egress, and Discord delivery are frozen.

Promotion requires all of the following:

- Frozen acceptance passes.
- At least 20 labeled findings, including positive and negative examples, exist.
- Precision is at least 80%.
- Recall and false-alert counter-metrics do not regress beyond policy.
- Multi-metric utility improves by at least two percentage points.
- Missing-source feedback does not contradict a stricter threshold.
- No injection/manipulation feedback is awaiting security review.
- Lobster pauses for explicit human approval.

Applying a proposal checks the base policy hash, writes a rollback snapshot, changes only the
allowlisted field, and writes an immutable receipt. Rollback checks the applied and snapshot hashes
before restoring the prior policy.

## Consequences

- The workflow safely stops with `insufficient_evidence` until real analyst labels accumulate.
- There is no automatic policy mutation and no path from a challenger to report delivery.
- Improving discovery queries, source trust, or safety policy requires a separate reviewed design;
  those parameters cannot be learned by this controller.
- The workflow can be scheduled weekly after the feedback process is operational, but it remains
  disabled in `config/schedules.yaml` until then.

## Reference

The loop/graph distinction follows the useful part of
[DevCompass's framing](https://www.devcompass.ai/blog/loop-engineering-vs-graph-engineering-part-1):
loops optimize a local cycle, graphs compose specialized loops with explicit state and routing, and
both still require grounded external anchors.
