from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from packages.scoring.engine import ScoreComponents


@dataclass(frozen=True, slots=True)
class ClusterSignals:
    first_observed_at: datetime
    evidence_count: int
    independent_source_count: int
    direct_artifact_count: int
    cvss_base_score: float | None
    epss_probability: float | None
    known_exploited: bool
    media_baseline_at: datetime | None
    organization_match: bool
    content_risk: str
    material_contradictions: int = 0


def compute_score(signals: ClusterSignals) -> ScoreComponents:
    cvss = signals.cvss_base_score or 0
    impact = round(min(25.0, max(0.0, cvss / 10 * 25)), 2)
    exploitability = round(min(20.0, max(0.0, (signals.epss_probability or 0) * 20)), 2)
    if signals.known_exploited:
        exploitability = 20.0
    evidence_strength = min(
        15.0,
        (6.0 if signals.direct_artifact_count else 2.0)
        + max(0, signals.independent_source_count - 1) * 3.0,
    )
    momentum = min(15.0, 4.0 + max(0, signals.evidence_count - 1) * 1.5)
    novelty = _novelty(signals.first_observed_at, signals.media_baseline_at)
    organization_relevance = 6.0 if signals.organization_match else 0.0
    penalties = 0.0
    if signals.independent_source_count <= 1 and signals.evidence_count > 1:
        penalties -= 10
    if signals.material_contradictions:
        penalties -= min(16, signals.material_contradictions * 8)
    if signals.content_risk in {"high", "critical"}:
        penalties -= 5
    reasons = (
        f"{signals.independent_source_count} independent source origin(s)",
        f"{signals.evidence_count} evidence item(s)",
        "known exploited" if signals.known_exploited else "not confirmed exploited",
        "media baseline absent" if signals.media_baseline_at is None else "media baseline present",
    )
    return ScoreComponents(
        impact=impact,
        exploitability=exploitability,
        evidence_strength=evidence_strength,
        momentum=momentum,
        novelty_lead_time=novelty,
        organization_relevance=organization_relevance,
        penalties=float(max(-30, penalties)),
        reasons=reasons,
    )


def _novelty(first_seen: datetime, media_baseline: datetime | None) -> float:
    if media_baseline is None:
        return 15.0
    lead_hours = (media_baseline - first_seen).total_seconds() / 3600
    if lead_hours <= 0:
        return 0.0
    return round(min(15.0, lead_hours / 168 * 15), 2)
