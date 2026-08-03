"""Deterministic Telemetry Research scoring.

Models may recommend feature values, but production values must be produced or
accepted by deterministic policy code before publication.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

import yaml


class PublicationClass(StrEnum):
    FLASH = "flash"
    WATCH = "watch"
    DAILY = "daily"
    ARCHIVE = "archive"


@dataclass(frozen=True, slots=True)
class PublicationThresholds:
    flash: float = 85.0
    watch: float = 65.0
    daily: float = 45.0

    def validate(self) -> None:
        if not 0 <= self.daily < self.watch < self.flash <= 100:
            raise ValueError(
                "publication thresholds must satisfy 0 <= daily < watch < flash <= 100"
            )

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> PublicationThresholds:
        thresholds = cls(
            flash=float(value["flash"]),
            watch=float(value["watch"]),
            daily=float(value["daily"]),
        )
        thresholds.validate()
        return thresholds


DEFAULT_THRESHOLDS = PublicationThresholds()


def load_thresholds(path: Path) -> PublicationThresholds:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("scoring configuration must be an object")
    raw_thresholds = value.get("thresholds")
    if not isinstance(raw_thresholds, dict):
        raise ValueError("scoring configuration omitted thresholds")
    return PublicationThresholds.from_mapping(raw_thresholds)


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
    thresholds: PublicationThresholds = DEFAULT_THRESHOLDS,
) -> PublicationClass:
    """Classify a finding while enforcing non-model policy gates."""
    thresholds.validate()
    if not citations_present:
        return PublicationClass.ARCHIVE

    total = score.total
    if (total >= thresholds.flash or direct_critical_rule) and flash_confirmation_rule:
        return PublicationClass.FLASH
    if total >= thresholds.watch:
        return PublicationClass.WATCH
    if total >= thresholds.daily:
        return PublicationClass.DAILY
    return PublicationClass.ARCHIVE
