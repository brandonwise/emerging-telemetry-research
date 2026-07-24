import json
import sqlite3
from pathlib import Path

import pytest

from packages.analytics.store import AnalyticsStore
from packages.pipeline.frozen import run_frozen_fixture


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
    finding_category = report["findings"][0]["category"]
    result.report_json_path.write_text(json.dumps(report), encoding="utf-8")
    store = AnalyticsStore(tmp_path / "state" / "radar.db")

    indexed = store.index_path(result.report_json_path)
    replay = store.index_path(result.report_json_path)
    overview = store.overview(days=365)
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

    synced = AnalyticsStore(tmp_path / "radar.db").sync_reports(report_root)

    assert synced == {"inserted": 1, "unchanged": 0, "skipped": 1}


def test_analytics_migrates_v1_to_taxonomy_schema(tmp_path: Path) -> None:
    database = tmp_path / "radar.db"
    with sqlite3.connect(database) as connection:
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
    with sqlite3.connect(database) as connection:
        version = connection.execute(
            "SELECT value FROM analytics_meta WHERE key = 'schema_version'"
        ).fetchone()
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    assert version == ("2",)
    assert {"analytics_finding_tags", "analytics_finding_sources"}.issubset(tables)
