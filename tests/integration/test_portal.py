from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from apps.portal.main import PortalSettings, create_app
from packages.pipeline.frozen import run_frozen_fixture


def _settings(tmp_path: Path, *, token: str | None = None) -> PortalSettings:
    return PortalSettings(
        analytics_db=tmp_path / "state" / "radar.db",
        reports_root=tmp_path / "reports",
        access_token=token,
    )


def test_portal_renders_reports_trends_and_exports(tmp_path: Path) -> None:
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        tmp_path / "reports" / "run_fixture_early",
    )
    client = TestClient(
        create_app(_settings(tmp_path)),
        client=("127.0.0.1", 50000),
    )

    dashboard = client.get("/")
    reports = client.get("/reports?q=CVE-2026")
    detail = client.get(f"/reports/{result.report['report_id']}")
    trends = client.get("/trends")
    csv_export = client.get("/exports/reports.csv")
    json_export = client.get("/exports/reports.json")

    assert dashboard.status_code == 200
    assert "Emerging threat radar" in dashboard.text
    assert 'style="' not in dashboard.text
    assert reports.status_code == 200
    assert result.report["report_id"] in reports.text
    assert detail.status_code == 200
    assert "Defensive checks" in detail.text
    assert trends.status_code == 200
    assert csv_export.headers["content-type"].startswith("text/csv")
    assert result.report["report_id"] in csv_export.text
    assert json_export.headers["content-disposition"].endswith(
        '"threat-radar-reports.json"'
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
    with pytest.raises(ValidationError, match="LAN mode requires"):
        PortalSettings(lan_mode=True, access_token="short")  # noqa: S106
