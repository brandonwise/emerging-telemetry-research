import json
from pathlib import Path
from typing import Literal

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from apps.portal.main import PortalSettings, create_app
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
    csv_export = client.get("/exports/reports.csv")
    json_export = client.get("/exports/reports.json")
    finding_csv_export = client.get("/exports/findings.csv")
    finding_json_export = client.get("/exports/findings.json")

    assert dashboard.status_code == 200
    assert "Emerging threat radar" in dashboard.text
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
    assert "Defensive checks" in detail.text
    assert "Where this was discovered" in detail.text
    assert "Researcher source post" in detail.text
    assert findings.status_code == 200
    assert "Supply Chain" in findings.text
    assert "X Post" in findings.text
    assert trends.status_code == 200
    assert "Cross-cutting themes" in trends.text
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
