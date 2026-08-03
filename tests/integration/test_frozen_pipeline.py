from pathlib import Path

from packages.audit.ledger import AuditLedger
from packages.delivery.discord import build_discord_delivery_plan
from packages.delivery.email import build_email_delivery_plan
from packages.delivery.local import build_local_delivery_plan
from packages.pipeline.frozen import run_frozen_fixture

FIXTURES = Path("tests/fixtures/vertical_slice")


def test_degraded_flash_run_completes_full_review_and_delivery_plan(tmp_path: Path) -> None:
    result = run_frozen_fixture(FIXTURES / "flash-manifest.json", tmp_path / "run")
    finding = result.report["findings"][0]
    assert finding["publication_class"] == "flash"
    assert finding["priority_score"] >= 85
    assert result.report["degraded_sources"] == ["cve-list-v5"]
    assert result.report["verification"]["all_claims_verified"] is True
    assert [item["agent_role"] for item in result.assessments] == [
        "specialist",
        "skeptic",
        "citation_verifier",
        "coordinator",
    ]
    plan = build_discord_delivery_plan(
        result.report,
        html_path=result.rendered.path,
        channel_id="1476283808587321451",
    )
    assert plan["report_id"] == result.report["report_id"]
    assert Path(plan["html_path"]).is_file()
    local_plan = build_local_delivery_plan(
        result.report,
        html_path=result.rendered.path,
    )
    assert local_plan["destination"] == "file:local"
    assert local_plan["report_id"] == result.report["report_id"]
    email_plan = build_email_delivery_plan(
        result.report,
        html_path=result.rendered.path,
        recipient="alerts@example.com",
    )
    assert email_plan["destination"].startswith("email:recipient:")
    assert email_plan["report_id"] == result.report["report_id"]
    records = tuple(
        __import__("json").loads(line)
        for line in result.audit_path.read_text(encoding="utf-8").splitlines()
    )
    AuditLedger.verify(records)


def test_early_signal_is_watch_before_media_fixture_is_revealed(tmp_path: Path) -> None:
    early = run_frozen_fixture(FIXTURES / "early-manifest.json", tmp_path / "early")
    later = run_frozen_fixture(FIXTURES / "late-manifest.json", tmp_path / "late")
    early_finding = early.report["findings"][0]
    later_finding = later.report["findings"][0]
    assert early_finding["publication_class"] == "watch"
    assert early_finding["lead_time_hours"] is None
    assert early_finding["novelty"] == "high"
    assert later_finding["lead_time_hours"] is None
    assert later_finding["media_baseline_at"] == "2026-07-22T19:00:00Z"
    assert later_finding["media_baseline_checked"] is True
    assert later_finding["score_components"]["novelty_lead_time"] == 0
    assert later_finding["priority_score"] < early_finding["priority_score"]


def test_replay_is_byte_for_byte_deterministic(tmp_path: Path) -> None:
    first = run_frozen_fixture(FIXTURES / "flash-manifest.json", tmp_path / "first")
    second = run_frozen_fixture(FIXTURES / "flash-manifest.json", tmp_path / "second")
    assert first.report_json_path.read_bytes() == second.report_json_path.read_bytes()
    assert first.rendered.path.read_bytes() == second.rendered.path.read_bytes()
    assert first.audit_path.read_bytes() == second.audit_path.read_bytes()
    assert first.rendered.rendered_html_hash == second.rendered.rendered_html_hash
