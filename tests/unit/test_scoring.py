from packages.scoring.engine import PublicationClass, ScoreComponents, classify


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
