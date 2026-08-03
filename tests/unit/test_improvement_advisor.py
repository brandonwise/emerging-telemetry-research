from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from packages.common.canonical import canonical_json_bytes, sha256_hex
from packages.improvement.advisor import run_advisory_cycle


def test_advisory_cycle_proposes_across_domains_without_mutating_policy(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    feedback = tmp_path / "feedback"
    reports.mkdir()
    feedback.mkdir()
    report = {
        "report_id": "rp_advisor_test",
        "source_health": [{"source_id": "source-a", "status": "degraded"}],
        "agent_reviews": [
            {
                "status": "failed",
                "failures": ["provider unavailable"],
                "assessments": [{"contradictions": ["sources disagree"]}],
            }
        ],
        "usage": [{"estimated_currency": 5.0}],
        "findings": [
            {
                "source_evidence": [
                    {"evidence_id": "ev_test", "injection_risk": "critical"}
                ]
            }
        ],
    }
    (reports / "report.json").write_bytes(canonical_json_bytes(report) + b"\n")
    for index in range(5):
        (feedback / f"feedback-{index}.json").write_text(
            json.dumps(
                {
                    "feedback_id": f"fb_{index}",
                    "taxonomy": "missing_material_source",
                }
            ),
            encoding="utf-8",
        )
    protected = {
        path: sha256_hex(path.read_bytes())
        for path in (
            Path("config/scoring.yaml"),
            Path("config/sources.yaml"),
            Path("policies/tool-policy.yaml"),
        )
    }

    result = run_advisory_cycle(
        reports_root=reports,
        feedback_root=feedback,
        mission_feedback_root=tmp_path / "mission-feedback",
        output_root=tmp_path / "advice",
        improvement_config=Path("config/improvement.yaml"),
        now=datetime(2026, 8, 3, 12, tzinfo=UTC),
    )

    domains = {item["domain"] for item in result["proposals"]}
    assert {
        "source_coverage",
        "source_reliability",
        "routing",
        "prompt",
        "cost",
        "security",
    } <= domains
    assert result["automatic_apply"] is False
    assert Path(str(result["advice_path"])).is_file()
    assert all(sha256_hex(path.read_bytes()) == digest for path, digest in protected.items())


def test_advisory_cycle_reports_no_change_without_evidence(tmp_path: Path) -> None:
    result = run_advisory_cycle(
        reports_root=tmp_path / "reports",
        feedback_root=tmp_path / "feedback",
        mission_feedback_root=tmp_path / "mission-feedback",
        output_root=tmp_path / "advice",
        improvement_config=Path("config/improvement.yaml"),
        now=datetime(2026, 8, 3, 12, tzinfo=UTC),
    )

    assert result["status"] == "no_change"
    assert result["proposals"] == []


def test_advisor_deduplicates_reports_and_reads_mission_feedback(tmp_path: Path) -> None:
    reports = tmp_path / "reports"
    mission_feedback = tmp_path / "mission-feedback"
    reports.mkdir()
    mission_feedback.mkdir()
    (reports / "report.json").write_text(
        json.dumps({"report_id": "mr_one", "outcomes": [], "usage": []}),
        encoding="utf-8",
    )
    (reports / "run-manifest.json").write_text(
        json.dumps({"report_id": "mr_one", "run_id": "run_one"}),
        encoding="utf-8",
    )
    for index in range(5):
        (mission_feedback / f"mf_{index}.json").write_text(
            json.dumps({"label": "not_useful"}),
            encoding="utf-8",
        )

    result = run_advisory_cycle(
        reports_root=reports,
        feedback_root=tmp_path / "feedback",
        mission_feedback_root=mission_feedback,
        output_root=tmp_path / "advice",
        improvement_config=Path("config/improvement.yaml"),
        now=datetime(2026, 8, 3, 12, tzinfo=UTC),
    )

    assert result["metrics"]["report_count"] == 1
    assert result["metrics"]["feedback_count"] == 5
    assert result["metrics"]["negative_feedback_rate"] == 1.0
    assert "calibration" in {proposal["domain"] for proposal in result["proposals"]}
