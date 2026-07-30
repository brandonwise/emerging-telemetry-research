import json
from pathlib import Path

from packages.evaluation.coverage_harness import evaluate_source_coverage


def test_source_coverage_eval_measures_surface_concentration(tmp_path: Path) -> None:
    report = {
        "discovery_telemetry": {
            "surfaces": [
                {
                    "source_id": "x-researchers",
                    "discovered_signal_count": 2,
                },
                {
                    "source_id": "reddit-security",
                    "discovered_signal_count": 3,
                },
                {
                    "source_id": "tiktok-security",
                    "discovered_signal_count": 1,
                },
                {
                    "source_id": "web-security-research",
                    "discovered_signal_count": 4,
                },
            ]
        },
        "findings": [
            {
                "source_evidence": [
                    {
                        "source_id": "x-researchers",
                        "source_type": "x_post",
                    },
                    {
                        "source_id": "reddit-security",
                        "source_type": "reddit_post",
                    },
                    {
                        "source_id": "tiktok-security",
                        "source_type": "tiktok_video",
                    },
                    {
                        "source_id": "web-security-research",
                        "source_type": "website",
                    },
                ]
            }
        ],
    }
    report_path = tmp_path / "reports" / "rp_test.json"
    report_path.parent.mkdir()
    report_path.write_text(json.dumps(report), encoding="utf-8")

    result = evaluate_source_coverage(
        reports_root=report_path.parent,
        output_root=tmp_path / "evaluation",
    )

    assert result["passed"] is True
    assert result["metrics"]["surface_count"] == 4
    assert result["metrics"]["x_share"] == 0.25
    assert result["metrics"]["largest_surface_share"] == 0.25
    assert result["metrics"]["discovered_signal_count"] == 10
    assert result["metrics"]["signal_surface_count"] == 4
    assert result["metrics"]["x_discovered_signal_share"] == 0.2


def test_source_coverage_eval_ignores_candidate_derivatives(tmp_path: Path) -> None:
    primary = {
        "discovery_telemetry": {
            "surfaces": [
                {"source_id": "one", "discovered_signal_count": 1},
                {"source_id": "two", "discovered_signal_count": 1},
                {"source_id": "three", "discovered_signal_count": 1},
                {"source_id": "four", "discovered_signal_count": 1},
            ]
        },
        "findings": [
            {
                "source_evidence": [
                    {"source_id": "one", "source_type": "website"},
                    {"source_id": "two", "source_type": "github_advisory"},
                    {"source_id": "three", "source_type": "reddit_post"},
                    {"source_id": "four", "source_type": "tiktok_video"},
                ]
            }
        ],
    }
    report_root = tmp_path / "reports"
    report_root.mkdir()
    (report_root / "rp_primary.json").write_text(json.dumps(primary), encoding="utf-8")
    candidate_dir = report_root / "candidates"
    candidate_dir.mkdir()
    (candidate_dir / "rp_candidate.json").write_text(json.dumps(primary), encoding="utf-8")

    result = evaluate_source_coverage(
        reports_root=report_root,
        output_root=tmp_path / "evaluation",
    )

    assert result["metrics"]["report_count"] == 1
    assert len(result["reports"]) == 1
