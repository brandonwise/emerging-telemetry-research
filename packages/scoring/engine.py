"""Deterministic Threat Radar scoring.

Models may recommend feature values, but production values must be produced or
accepted by deterministic policy code before publication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class PublicationClass(StrEnum):
    FLASH = "flash"
    WATCH = "watch"
    DAILY = "daily"
    ARCHIVE = "archive"


@dataclass(frozen=True, slots=True)
class ScoreComponents:
    impact: float
    exploitability: float
    evidence_strength: float
    momentum: float
    novelty_lead_time: float
    organization_relevance: float
    penalties: float = 0.0
    reasons: tuple[str, ...] = field(default_factory=tuple)

    def validate(self) -> None:
        ranges = {
            "impact": (self.impact, 0, 25),
            "exploitability": (self.exploitability, 0, 20),
            "evidence_strength": (self.evidence_strength, 0, 15),
            "momentum": (self.momentum, 0, 15),
            "novelty_lead_time": (self.novelty_lead_time, 0, 15),
            "organization_relevance": (self.organization_relevance, 0, 10),
            "penalties": (self.penalties, -30, 0),
        }
        for name, (value, lower, upper) in ranges.items():
            if not lower <= value <= upper:
                raise ValueError(f"{name}={value} is outside [{lower}, {upper}]")

    @property
    def total(self) -> float:
        self.validate()
        raw = (
            self.impact
            + self.exploitability
            + self.evidence_strength
            + self.momentum
            + self.novelty_lead_time
            + self.organization_relevance
            + self.penalties
        )
        return round(max(0.0, min(100.0, raw)), 2)


def classify(
    score: ScoreComponents,
    *,
    direct_critical_rule: bool = False,
    citations_present: bool = True,
    flash_confirmation_rule: bool = False,
) -> PublicationClass:
    """Classify a finding while enforcing non-model policy gates."""
    if not citations_present:
        return PublicationClass.ARCHIVE

    total = score.total
    if (total >= 85 or direct_critical_rule) and flash_confirmation_rule:
        return PublicationClass.FLASH
    if total >= 65:
        return PublicationClass.WATCH
    if total >= 45:
        return PublicationClass.DAILY
    return PublicationClass.ARCHIVE
