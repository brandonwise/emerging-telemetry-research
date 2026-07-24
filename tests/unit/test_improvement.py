from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from packages.common.canonical import canonical_json_bytes, stable_id
from packages.improvement.controller import (
    apply_proposal,
    rollback_proposal,
    run_improvement_cycle,
)


def test_improvement_cycle_requires_grounded_sample_gate(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    _stub_acceptance(monkeypatch)
    scoring = _copy_scoring_config(tmp_path)
    result = run_improvement_cycle(
        reports_root=tmp_path / "reports",
        feedback_root=tmp_path / "feedback",
        output_root=tmp_path / "cycles",
        fixture_root=Path("tests/fixtures/vertical_slice"),
        scoring_config=scoring,
        improvement_config=Path("config/improvement.yaml"),
        now=datetime(2026, 7, 24, 13, 0, tzinfo=UTC),
    )

    assert result["status"] == "insufficient_evidence"
    assert result["proposal_path"] is None
    assert result["anchors"]["acceptance_passed"] is True
    assert frozenset({"observe", "acceptance"}) in {
        frozenset(layer) for layer in result["graph"]["layers"]
    }


def test_bounded_challenger_apply_and_rollback(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    _stub_acceptance(monkeypatch)
    scoring = _copy_scoring_config(tmp_path)
    reports = tmp_path / "reports"
    feedback = tmp_path / "feedback"
    reports.mkdir()
    feedback.mkdir()
    created_at = datetime(2026, 7, 24, 12, 0, tzinfo=UTC)
    scores = [80.0] * 8 + [47.0] * 5 + [30.0] * 7
    positive = [True] * 8 + [False] * 12
    for index, (score, is_positive) in enumerate(zip(scores, positive, strict=True)):
        report_id = f"rp_test_{index:02d}"
        finding_id = f"fd_test_{index:02d}"
        (reports / f"{report_id}.json").write_bytes(
            canonical_json_bytes(
                {
                    "report_id": report_id,
                    "findings": [
                        {
                            "finding_id": finding_id,
                            "priority_score": score,
                        }
                    ],
                }
            )
            + b"\n"
        )
        feedback_id = stable_id("fb", report_id, finding_id)
        (feedback / f"{feedback_id}.json").write_bytes(
            canonical_json_bytes(
                {
                    "schema_version": "1.0",
                    "feedback_id": feedback_id,
                    "report_id": report_id,
                    "finding_id": finding_id,
                    "taxonomy": (
                        "actionable_and_early"
                        if is_positive
                        else "incorrect_interpretation"
                    ),
                    "notes": None,
                    "submitted_by": "unit-test",
                    "created_at": (created_at + timedelta(seconds=index)).isoformat(),
                }
            )
            + b"\n"
        )

    result = run_improvement_cycle(
        reports_root=reports,
        feedback_root=feedback,
        output_root=tmp_path / "cycles",
        fixture_root=Path("tests/fixtures/vertical_slice"),
        scoring_config=scoring,
        improvement_config=Path("config/improvement.yaml"),
        now=datetime(2026, 7, 24, 13, 0, tzinfo=UTC),
    )

    assert result["status"] == "approval_required"
    proposal = Path(str(result["proposal_path"]))
    proposal_value = json.loads(proposal.read_text(encoding="utf-8"))
    assert proposal_value["changes"] == [
        {"path": "thresholds.daily", "from": 45.0, "to": 50.0}
    ]

    applied = apply_proposal(
        proposal,
        repo_root=tmp_path,
        approved_by="unit-test",
        approval_id="approval_001",
    )
    changed = yaml.safe_load(scoring.read_text(encoding="utf-8"))
    assert changed["thresholds"]["daily"] == 50
    assert applied["status"] == "applied"

    rolled_back = rollback_proposal(
        Path(str(applied["receipt_path"])),
        repo_root=tmp_path,
        approved_by="unit-test",
        approval_id="rollback_001",
    )
    restored = yaml.safe_load(scoring.read_text(encoding="utf-8"))
    assert restored["thresholds"]["daily"] == 45
    assert rolled_back["status"] == "rolled_back"


def _copy_scoring_config(tmp_path: Path) -> Path:
    config = tmp_path / "config"
    config.mkdir()
    scoring = config / "scoring.yaml"
    scoring.write_bytes(Path("config/scoring.yaml").read_bytes())
    return scoring


def _stub_acceptance(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "packages.improvement.controller.run_acceptance_suite",
        lambda *_args, **_kwargs: {
            "passed": True,
            "gates": {"privileged_injection_success": 0},
        },
    )
