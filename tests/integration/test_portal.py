import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

import apps.portal.main as portal_main
from apps.portal.main import PortalSettings, _inline_style_hash, _unique_findings, create_app
from packages.missions.compiler import load_mission
from packages.missions.runtime import run_mission
from packages.pipeline.frozen import run_frozen_fixture


def _settings(
    tmp_path: Path,
    *,
    token: str | None = None,
    auth_mode: Literal["auto", "required", "disabled"] = "auto",
    lan_mode: bool = False,
) -> PortalSettings:
    return PortalSettings(
        analytics_db=tmp_path / "state" / "radar.db",
        reports_root=tmp_path / "reports",
        auth_mode=auth_mode,
        access_token=token,
        lan_mode=lan_mode,
    )


def test_portal_mission_onboarding_and_report_navigation(tmp_path: Path) -> None:
    mission = load_mission(Path("missions/developer-product-opportunities/mission.yaml"))
    signals = json.loads(
        Path("missions/developer-product-opportunities/fixture-signals.json").read_text(
            encoding="utf-8"
        )
    )
    result = asyncio.run(
        run_mission(
            mission,
            signals,
            tmp_path / "mission-reports",
            generated_at=datetime(2026, 7, 31, 12, tzinfo=UTC),
        )
    )
    settings = _settings(tmp_path)
    settings.missions_root = Path("missions")
    settings.mission_reports_root = tmp_path / "mission-reports"
    client = TestClient(
        create_app(settings),
        client=("127.0.0.1", 50000),
    )

    index = client.get("/missions")
    builder = client.get(
        "/missions/new",
        params={
            "objective": "Find recurring developer workflow pain worth solving with a product."
        },
    )
    download = client.get(
        "/missions/download",
        params={
            "objective": "Find recurring developer workflow pain worth solving with a product."
        },
    )
    detail = client.get(f"/missions/{mission.mission_id}")
    report = client.get(
        f"/missions/{mission.mission_id}/reports/{result.report['report_id']}"
    )

    assert index.status_code == 200
    assert "Developer Product Opportunity Radar" in index.text
    assert builder.status_code == 200
    assert "Build research plan" in builder.text
    assert "Download mission" in builder.text
    assert download.status_code == 200
    assert "attachment;" in download.headers["content-disposition"]
    assert detail.status_code == 200
    assert "Five bounded roles" in detail.text
    assert report.status_code == 200
    assert "Automate disposable local test environments" in report.text


def test_priority_queue_deduplicates_recurring_findings() -> None:
    rows = [
        {"finding_id": "finding-a", "priority_score": 90.0},
        {"finding_id": "finding-a", "priority_score": 85.0},
        {"finding_id": "finding-b", "priority_score": 80.0},
    ]

    assert _unique_findings(rows, limit=2) == [rows[0], rows[2]]


def test_architecture_csp_hash_tracks_document_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    architecture_path = tmp_path / "architecture-motion.html"
    architecture_path.write_text(
        portal_main.ARCHITECTURE_MOTION_PATH.read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    monkeypatch.setattr(portal_main, "ARCHITECTURE_MOTION_PATH", architecture_path)
    client = TestClient(
        create_app(_settings(tmp_path)),
        client=("127.0.0.1", 50000),
    )
    architecture_path.write_text(
        architecture_path.read_text(encoding="utf-8").replace(
            "--bg: #06110f;",
            "--bg: #07120f;",
            1,
        ),
        encoding="utf-8",
    )

    architecture = client.get("/architecture")

    expected_hash = _inline_style_hash(architecture.text)
    assert f"style-src 'sha256-{expected_hash}'" in architecture.headers["content-security-policy"]


def test_portal_renders_reports_trends_and_exports(tmp_path: Path) -> None:
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        tmp_path / "reports" / "run_fixture_early",
    )
    report = json.loads(result.report_json_path.read_text(encoding="utf-8"))
    report["findings"][0]["tags"] = ["ai", "supply_chain"]
    report["findings"][0]["source_evidence"] = [
        {
            "evidence_id": "ev_portal_discovery",
            "source_id": "x-researchers",
            "source_type": "x_post",
            "title": "Researcher source post",
            "url": "https://x.com/researcher/status/123",
            "published_at": "2026-07-22T10:00:00Z",
            "retrieved_at": "2026-07-22T11:00:00Z",
            "excerpt": "The original source-native discovery excerpt.",
            "source_handle": "researcher",
        }
    ]
    report["usage"].append(
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
        }
    )
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
    report["semantic_shadow"] = {
        "mode": "shadow",
        "status": "completed",
        "provider": "ollama",
        "model": "nomic-embed-text:latest",
        "similarity_threshold": 0.78,
        "discovered_signal_count": 12,
        "evaluated_signal_count": 12,
        "truncated_signal_count": 0,
        "deterministic_pair_count": 3,
        "candidate_pair_count": 5,
        "overlap_pair_count": 3,
        "semantic_only_pair_count": 2,
        "deterministic_only_pair_count": 0,
        "requests": 1,
        "input_tokens": 240,
        "duration_ms": 130,
        "vector_dimensions": 768,
        "failure_reason": None,
        "candidate_pairs": [],
        "publication_authority": False,
    }
    report["usage"].append(
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
        }
    )
    finding_category = report["findings"][0]["category"]
    result.report_json_path.write_text(json.dumps(report), encoding="utf-8")
    client = TestClient(
        create_app(_settings(tmp_path)),
        client=("127.0.0.1", 50000),
    )

    dashboard = client.get("/")
    settings = client.get("/setup")
    reports = client.get("/reports?q=CVE-2026")
    detail = client.get(f"/reports/{result.report['report_id']}")
    findings = client.get(f"/findings?category={finding_category}&tag=ai&source=x_post")
    trends = client.get("/trends")
    architecture = client.get("/architecture")
    architecture_blueprint = client.get("/architecture/blueprint")
    architecture_gif = client.get("/exports/architecture.gif")
    csv_export = client.get("/exports/reports.csv")
    json_export = client.get("/exports/reports.json")
    finding_csv_export = client.get("/exports/findings.csv")
    finding_json_export = client.get("/exports/findings.json")
    favicon = client.get("/static/radar-mark.svg")

    assert dashboard.status_code == 200
    assert "The threat picture," in dashboard.text
    assert "right now." in dashboard.text
    assert "Evidence diversity" in dashboard.text
    assert "100.0% X" in dashboard.text
    assert "What these numbers actually count" in dashboard.text
    assert "Operational telemetry only" in dashboard.text
    assert "Fixtures and evals" in dashboard.text
    assert "Early warning" not in dashboard.text
    assert "No live agent reviews in this window" in dashboard.text
    assert "Usage estimate" not in dashboard.text
    assert settings.status_code == 200
    assert "Configuration and usage" in settings.text
    assert "Usage value, not necessarily cash spend." in settings.text
    assert "Brave Search is estimated at $5 per 1,000 requests" in settings.text
    assert "Semantic clustering shadow" in settings.text
    assert "nomic-embed-text:latest" in settings.text
    assert "Potentially missed pairs" in settings.text
    assert "grok-4.5" in settings.text
    assert "$0.2750" in settings.text
    assert 'style="' not in dashboard.text
    assert reports.status_code == 200
    assert result.report["report_id"] in reports.text
    assert detail.status_code == 200
    assert "Deterministic score anatomy" in detail.text
    assert "Claim ledger" in detail.text
    assert "Defensive checks" in detail.text
    assert "Where this was discovered" in detail.text
    assert "Researcher source post" in detail.text
    assert findings.status_code == 200
    assert "Supply Chain" in findings.text
    assert "X Post" in findings.text
    assert trends.status_code == 200
    assert "Cross-cutting themes" in trends.text
    assert "Evidence by source type" in trends.text
    assert "Fixture and evaluation reports are excluded" in trends.text
    assert 'href="/architecture"' in dashboard.text
    assert architecture.status_code == 200
    assert "See the system" in architecture.text
    assert "<animateMotion" in architecture.text
    assert 'href="/architecture/blueprint"' in architecture.text
    assert 'href="/exports/architecture.gif"' in architecture.text
    assert 'download="threat-radar-architecture-motion.gif"' in architecture.text
    assert 'href="/">Return to command center' in architecture.text
    assert "style-src 'sha256-" in architecture.headers["content-security-policy"]
    assert "'unsafe-inline'" not in architecture.headers["content-security-policy"]
    assert architecture.headers["x-frame-options"] == "DENY"
    assert architecture_blueprint.status_code == 200
    assert "Emerging Threat Radar, end to end" in architecture_blueprint.text
    assert 'href="/architecture"' in architecture_blueprint.text
    assert 'href="/">← Command center' in architecture_blueprint.text
    assert architecture_gif.status_code == 200
    assert architecture_gif.headers["content-type"] == "image/gif"
    assert architecture_gif.headers["content-disposition"].endswith(
        'filename="threat-radar-architecture-motion.gif"'
    )
    assert architecture_gif.content.startswith(b"GIF89a")
    assert int.from_bytes(architecture_gif.content[6:8], "little") == 3360
    assert int.from_bytes(architecture_gif.content[8:10], "little") == 1960
    assert architecture_gif.content.count(b"\x21\xf9\x04") >= 48
    assert csv_export.headers["content-type"].startswith("text/csv")
    assert result.report["report_id"] in csv_export.text
    assert json_export.headers["content-disposition"].endswith('"threat-radar-reports.json"')
    assert finding_csv_export.status_code == 200
    assert "supply_chain" in finding_csv_export.text
    assert finding_json_export.status_code == 200
    assert finding_json_export.headers["content-disposition"].endswith(
        '"threat-radar-findings.json"'
    )
    assert dashboard.headers["x-frame-options"] == "DENY"
    assert favicon.status_code == 200
    assert favicon.headers["content-type"].startswith("image/svg+xml")


def test_portal_token_authentication(tmp_path: Path) -> None:
    token = "a-strong-private-lan-token"  # noqa: S105
    client = TestClient(
        create_app(_settings(tmp_path, token=token)),
        client=("127.0.0.1", 50000),
        follow_redirects=False,
    )

    blocked = client.get("/")
    invalid = client.post(
        "/login",
        content="token=wrong",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )
    authenticated = client.post(
        "/login",
        content=f"token={token}",
        headers={"content-type": "application/x-www-form-urlencoded"},
    )

    assert blocked.status_code == 303
    assert blocked.headers["location"] == "/login"
    assert invalid.status_code == 401
    assert authenticated.status_code == 303
    assert "radar_session=" in authenticated.headers["set-cookie"]
    assert "HttpOnly" in authenticated.headers["set-cookie"]
    assert "SameSite=strict" in authenticated.headers["set-cookie"]


def test_lan_mode_requires_a_strong_token() -> None:
    with pytest.raises(ValidationError, match="authentication mode requires"):
        PortalSettings(lan_mode=True, access_token="short")  # noqa: S106


def test_lan_authentication_can_be_explicitly_disabled(tmp_path: Path) -> None:
    settings = _settings(
        tmp_path,
        token="a-token-that-must-not-be-used",  # noqa: S106
        auth_mode="disabled",
        lan_mode=True,
    )
    client = TestClient(
        create_app(settings),
        client=("192.168.100.25", 50000),
        follow_redirects=False,
    )

    dashboard = client.get("/")
    login = client.get("/login")
    export = client.get("/exports/reports.json")
    untrusted_client = TestClient(
        create_app(settings),
        client=("203.0.113.25", 50000),
        follow_redirects=False,
    )

    assert settings.authentication_enabled is False
    assert settings.effective_access_token() is None
    assert dashboard.status_code == 200
    assert "Sign out" not in dashboard.text
    assert "Trusted network only" in client.get("/setup").text
    assert login.status_code == 303
    assert login.headers["location"] == "/"
    assert export.status_code == 200
    assert untrusted_client.get("/").status_code == 403


def test_required_authentication_needs_a_token() -> None:
    with pytest.raises(ValidationError, match="authentication mode requires"):
        PortalSettings(auth_mode="required")
