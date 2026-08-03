import json
import sqlite3
from contextlib import closing
from pathlib import Path

import pytest

from packages.analytics.store import AnalyticsStore
from packages.pipeline.frozen import run_frozen_fixture


def _mark_operational(report: dict[str, object]) -> None:
    report["discovery_telemetry"] = {
        "discovered_signal_count": 1,
        "prepared_signal_count": 1,
        "cited_evidence_count": 1,
        "surfaces": [
            {
                "source_id": "x-researchers",
                "status": "healthy",
                "requests": 1,
                "discovered_signal_count": 1,
                "prepared_signal_count": 1,
                "selected_finding_count": 1,
                "cited_evidence_count": 1,
                "source_types": ["x_post"],
            }
        ],
    }


def test_report_index_builds_overview_trends_and_bounded_events(tmp_path: Path) -> None:
    report_root = tmp_path / "reports" / "run_fixture_early"
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        report_root,
    )
    report = json.loads(result.report_json_path.read_text(encoding="utf-8"))
    report["findings"][0]["tags"] = ["ai", "supply_chain"]
    report["findings"][0]["source_evidence"] = [
        {
            "evidence_id": "ev_discovery_example",
            "source_id": "x-researchers",
            "source_type": "x_post",
            "title": "Researcher discovery",
            "url": "https://x.com/researcher/status/123",
            "published_at": "2026-07-22T10:00:00Z",
            "retrieved_at": "2026-07-22T11:00:00Z",
            "excerpt": "A source-native discovery excerpt.",
            "source_handle": "researcher",
        }
    ]
    report["usage"].extend(
        [
            {
                "stage": "social_discovery",
                "agent_id": None,
                "source_id": "x-researchers",
                "finding_id": None,
                "provider": "xai",
                "model": "grok-4.5",
                "requests": 1,
                "input_tokens": 1200,
                "output_tokens": 300,
                "estimated_currency": 0.25,
            },
            {
                "stage": "web_discovery",
                "agent_id": None,
                "source_id": "brave-web",
                "finding_id": None,
                "provider": "brave",
                "model": "brave-web-search-v1",
                "requests": 5,
                "input_tokens": 0,
                "output_tokens": 0,
                "estimated_currency": 0,
            },
        ]
    )
    _mark_operational(report)
    finding_category = report["findings"][0]["category"]
    result.report_json_path.write_text(json.dumps(report), encoding="utf-8")
    store = AnalyticsStore(tmp_path / "state" / "radar.db")

    indexed = store.index_path(result.report_json_path)
    replay = store.index_path(result.report_json_path)
    overview = store.overview(days=365)
    intelligence = store.intelligence_summary(days=365)
    costs = store.cost_breakdown(days=365)
    reports = store.list_reports(query="CVE-2026")
    findings = store.list_findings(
        category=finding_category,
        tag="ai",
        source_type="x_post",
    )
    taxonomy = store.taxonomy_counts(days=365)
    trend = store.daily_trend(days=365)
    event_id = store.record_event(
        metric="portal.exported",
        value=1,
        unit="export",
        dimensions={"format": "csv"},
    )

    assert indexed.inserted is True
    assert replay.inserted is False
    assert overview["reports"] == 1
    assert overview["findings"] == 1
    assert intelligence["source_count"] == 1
    assert intelligence["high_priority"] == 1
    assert intelligence["evidence_count"] == 1
    assert intelligence["x_share"] == 100.0
    assert intelligence["non_x_evidence"] == 0
    assert intelligence["claim_count"] == 2
    assert intelligence["verified_claim_count"] == 2
    assert intelligence["claim_verification_rate"] == 100.0
    assert intelligence["sources"] == [
        {
            "source_type": "x_post",
            "evidence": 1,
            "source_count": 1,
            "share": 100.0,
            "width": 10,
        }
    ]
    assert costs["estimated_cost"] == 0.275
    assert costs["requests"] == 10
    assert costs["tokens"] == 1500
    assert costs["average_per_report"] == 0.275
    assert costs["providers"][0] == {
        "provider": "xai",
        "model": "grok-4.5",
        "requests": 1,
        "tokens": 1500,
        "estimated_cost": 0.25,
        "cost_share": 90.9,
    }
    assert costs["providers"][1] == {
        "provider": "brave",
        "model": "brave-web-search-v1",
        "requests": 5,
        "tokens": 0,
        "estimated_cost": 0.025,
        "cost_share": 9.1,
    }
    assert {item["stage"] for item in costs["stages"]} >= {
        "social_discovery",
        "web_discovery",
    }
    assert reports[0]["report_id"] == result.report["report_id"]
    assert findings[0]["tags"] == ["ai", "supply_chain"]
    assert findings[0]["source_types"] == ["x_post"]
    assert taxonomy["categories"][0]["name"] == finding_category
    assert {item["name"] for item in taxonomy["tags"]} == {"ai", "supply_chain"}
    assert trend[0]["findings"] == 1
    assert event_id.startswith("evt_")
    assert {item["metric"] for item in store.event_summary(days=365)} == {
        "portal.exported",
        "report.indexed",
    }
    assert store.overview(days=365)["events"] == 2


def test_analytics_rejects_mutated_report_and_unbounded_dimensions(tmp_path: Path) -> None:
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        tmp_path / "reports" / "run_fixture_early",
    )
    store = AnalyticsStore(tmp_path / "radar.db")
    store.index_path(result.report_json_path)
    mutated = json.loads(result.report_json_path.read_text(encoding="utf-8"))
    mutated["executive_summary"] = "A different immutable report."

    with pytest.raises(ValueError, match="immutable analytics conflict"):
        store.index_report(
            mutated,
            report_path=result.report_json_path,
            html_path=result.rendered.path,
        )
    with pytest.raises(ValueError, match="bounded limits"):
        store.record_event(
            metric="invalid",
            value=1,
            unit="event",
            dimensions={f"key-{index}": "value" for index in range(21)},
        )


def test_sync_skips_candidate_reports(tmp_path: Path) -> None:
    report_root = tmp_path / "reports"
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        report_root / "run_fixture_early",
    )
    candidate = report_root / "run_fixture_early" / "candidates" / "CVE-2026-9999"
    candidate.mkdir(parents=True)
    (candidate / result.report_json_path.name).write_bytes(result.report_json_path.read_bytes())
    report = json.loads(result.report_json_path.read_text(encoding="utf-8"))
    _mark_operational(report)
    result.report_json_path.write_text(json.dumps(report), encoding="utf-8")

    synced = AnalyticsStore(tmp_path / "radar.db").sync_reports(report_root)

    assert synced == {"inserted": 1, "unchanged": 0, "skipped": 1, "excluded": 0}


def test_sync_skips_auxiliary_evaluation_reports(tmp_path: Path) -> None:
    report_root = tmp_path / "reports"
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        report_root / "run_fixture_early",
    )
    report = json.loads(result.report_json_path.read_text(encoding="utf-8"))
    _mark_operational(report)
    result.report_json_path.write_text(json.dumps(report), encoding="utf-8")
    evaluation = report_root / "evaluation" / "early"
    evaluation.mkdir(parents=True)
    mutated = json.loads(result.report_json_path.read_text(encoding="utf-8"))
    mutated["executive_summary"] = "Conflicting evaluation-only copy."
    (evaluation / result.report_json_path.name).write_text(
        json.dumps(mutated),
        encoding="utf-8",
    )

    synced = AnalyticsStore(tmp_path / "radar.db").sync_reports(report_root)

    assert synced == {"inserted": 1, "unchanged": 0, "skipped": 1, "excluded": 0}


def test_analytics_migrates_v1_to_usage_schema(tmp_path: Path) -> None:
    database = tmp_path / "radar.db"
    with closing(sqlite3.connect(database)) as connection:
        connection.execute(
            "CREATE TABLE analytics_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        connection.execute(
            "INSERT INTO analytics_meta (key, value) VALUES ('schema_version', '1')"
        )

    store = AnalyticsStore(database)

    assert store.taxonomy_options() == {
        "categories": [],
        "tags": [],
        "source_types": [],
    }
    with closing(sqlite3.connect(database)) as connection:
        version = connection.execute(
            "SELECT value FROM analytics_meta WHERE key = 'schema_version'"
        ).fetchone()
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert version == ("4",)
    assert {
        "analytics_finding_tags",
        "analytics_finding_sources",
        "analytics_usage",
    }.issubset(tables)


def test_operational_metrics_dedupe_recurring_findings_and_exclude_fixtures(
    tmp_path: Path,
) -> None:
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        tmp_path / "reports" / "run_fixture_early",
    )
    first = json.loads(result.report_json_path.read_text(encoding="utf-8"))
    _mark_operational(first)
    first["report_id"] = "rp_operational_first"
    first["findings"][0]["tags"] = ["first"]
    second = json.loads(json.dumps(first))
    second["report_id"] = "rp_operational_repeat"
    second["generated_at"] = "2026-07-23T13:30:00Z"
    second["findings"][0]["priority_score"] = 50
    second["findings"][0]["tags"] = ["latest"]
    fixture = json.loads(json.dumps(second))
    fixture.pop("discovery_telemetry")
    fixture["report_id"] = "rp_fixture_contamination"
    fixture["generated_at"] = "2026-07-24T13:30:00Z"
    fixture["findings"][0]["priority_score"] = 99
    fixture["findings"][0]["tags"] = ["fixture-only"]
    store = AnalyticsStore(tmp_path / "radar.db")

    first_result = store.index_report(
        first,
        report_path=result.report_json_path,
        html_path=result.rendered.path,
    )
    second_result = store.index_report(
        second,
        report_path=result.report_json_path,
        html_path=result.rendered.path,
    )
    fixture_result = store.index_report(
        fixture,
        report_path=result.report_json_path,
        html_path=result.rendered.path,
    )

    assert first_result.telemetry_scope == "operational"
    assert second_result.telemetry_scope == "operational"
    assert fixture_result.telemetry_scope == "fixture"
    assert store.overview(days=365)["reports"] == 2
    assert store.overview(days=365)["findings"] == 1
    assert store.intelligence_summary(days=365)["findings"] == 1
    assert store.list_findings(days=365)[0]["priority_score"] == 50
    assert store.taxonomy_counts(days=365)["tags"] == [
        {"name": "latest", "findings": 1}
    ]
