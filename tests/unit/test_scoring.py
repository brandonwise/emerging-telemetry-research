from datetime import UTC, datetime, timedelta

from packages.scoring.engine import (
    PublicationClass,
    PublicationThresholds,
    ScoreComponents,
    classify,
)
from packages.scoring.features import ClusterSignals, compute_score


def _signals(
    *,
    first_observed_at: datetime,
    evaluated_at: datetime,
    media_baseline_at: datetime | None,
    media_baseline_checked: bool,
) -> ClusterSignals:
    return ClusterSignals(
        first_observed_at=first_observed_at,
        evaluated_at=evaluated_at,
        evidence_count=3,
        independent_source_count=2,
        direct_artifact_count=1,
        cvss_base_score=8.0,
        epss_probability=0.5,
        known_exploited=False,
        media_baseline_at=media_baseline_at,
        media_baseline_checked=media_baseline_checked,
        organization_match=False,
        content_risk="low",
    )


def test_total_and_flash_gate() -> None:
    score = ScoreComponents(
        impact=25,
        exploitability=18,
        evidence_strength=15,
        momentum=12,
        novelty_lead_time=12,
        organization_relevance=8,
    )
    assert score.total == 90
    assert classify(score, flash_confirmation_rule=False) == PublicationClass.WATCH
    assert classify(score, flash_confirmation_rule=True) == PublicationClass.FLASH


def test_missing_citation_archives() -> None:
    score = ScoreComponents(25, 20, 15, 15, 15, 10)
    assert (
        classify(score, citations_present=False, flash_confirmation_rule=True)
        == PublicationClass.ARCHIVE
    )


def test_daily_threshold_is_configurable_but_ordered() -> None:
    score = ScoreComponents(10, 10, 10, 10, 7, 0)
    assert classify(score) == PublicationClass.DAILY
    assert (
        classify(
            score,
            thresholds=PublicationThresholds(flash=85, watch=65, daily=50),
        )
        == PublicationClass.ARCHIVE
    )


def test_unmeasured_media_baseline_gets_no_novelty_credit() -> None:
    evaluated_at = datetime(2026, 7, 31, 12, tzinfo=UTC)
    score = compute_score(
        _signals(
            first_observed_at=evaluated_at - timedelta(hours=1),
            evaluated_at=evaluated_at,
            media_baseline_at=None,
            media_baseline_checked=False,
        )
    )
    assert score.novelty_lead_time == 0
    assert "media baseline not measured" in score.reasons


def test_measured_absent_baseline_uses_age_bounded_freshness() -> None:
    evaluated_at = datetime(2026, 7, 31, 12, tzinfo=UTC)
    fresh = compute_score(
        _signals(
            first_observed_at=evaluated_at - timedelta(hours=1),
            evaluated_at=evaluated_at,
            media_baseline_at=None,
            media_baseline_checked=True,
        )
    )
    stale = compute_score(
        _signals(
            first_observed_at=evaluated_at - timedelta(days=8),
            evaluated_at=evaluated_at,
            media_baseline_at=None,
            media_baseline_checked=True,
        )
    )
    assert 14 < fresh.novelty_lead_time < 15
    assert stale.novelty_lead_time == 0


def test_existing_media_baseline_gets_no_novelty_credit() -> None:
    evaluated_at = datetime(2026, 7, 31, 12, tzinfo=UTC)
    score = compute_score(
        _signals(
            first_observed_at=evaluated_at - timedelta(hours=1),
            evaluated_at=evaluated_at,
            media_baseline_at=evaluated_at - timedelta(minutes=30),
            media_baseline_checked=True,
        )
    )
    assert score.novelty_lead_time == 0
