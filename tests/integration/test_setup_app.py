from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

import apps.setup.main as setup_main
from apps.setup.main import SetupSettings, _control_paths, _csrf_value, create_app
from packages.missions.compiler import compile_mission, load_mission
from packages.onboarding.harnesses import HarnessStatus
from packages.security_gateway.deployment import require_deployment_approval

TOKEN = "local-test-token-with-more-than-24-characters"  # noqa: S105 - test-only value.


def _client(tmp_path: Path) -> TestClient:
    return TestClient(
        create_app(
            SetupSettings(
                project_root=tmp_path,
                access_token=TOKEN,
                testing=True,
            )
        )
    )


def _login(client: TestClient) -> None:
    response = client.get(f"/login?token={TOKEN}", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/"


def test_setup_requires_loopback_session_and_consumes_startup_token(tmp_path: Path) -> None:
    client = _client(tmp_path)

    denied = client.get("/", follow_redirects=False)
    assert denied.status_code == 303
    assert denied.headers["location"] == "/login"
    _login(client)
    home = client.get("/")
    assert home.status_code == 200
    assert "Research setup" in home.text
    assert "default-src 'none'" in home.headers["content-security-policy"]

    second_client = TestClient(client.app)
    reused = second_client.get(f"/login?token={TOKEN}", follow_redirects=False)
    assert reused.status_code == 401


def test_nontechnical_setup_creates_private_config_and_reviewable_mission(
    tmp_path: Path,
) -> None:
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf_value(TOKEN)

    initialized = client.post(
        "/initialize",
        data={"csrf": csrf, "profile": "portable"},
        follow_redirects=False,
    )
    assert initialized.status_code == 303
    config = tmp_path / ".emerging-telemetry-research/config.env"
    assert config.is_file()
    assert "ETR_PROFILE=portable" in config.read_text(encoding="utf-8")

    approved = client.post(
        "/deployment-approval",
        data={
            "csrf": csrf,
            "approved_by": "Research owner",
            "approval_id": "local-deployment-test",
            "expires_days": "30",
        },
        follow_redirects=False,
    )
    assert approved.status_code == 303
    deployment_approval = require_deployment_approval(
        "collection",
        approval_path=(
            tmp_path / ".emerging-telemetry-research/deployment-approval.yaml"
        ),
        paths=_control_paths(tmp_path),
    )
    assert deployment_approval["capabilities"] == {
        "collection": True,
        "external_delivery": False,
        "self_improvement_apply": False,
    }

    configured = client.post(
        "/agent",
        data={
            "csrf": csrf,
            "adapter": "codex",
            "mode": "plan",
            "model": "",
            "base_url": "",
            "provider_name": "",
        },
        follow_redirects=False,
    )
    assert configured.status_code == 303
    assert "ETR_AGENT_ADAPTER=codex" in config.read_text(encoding="utf-8")

    created = client.post(
        "/mission",
        data={
            "csrf": csrf,
            "objective": (
                "Find recurring customer onboarding problems our support team can fix this quarter."
            ),
            "result_type": "problem",
            "window_hours": "168",
            "cadence": "daily",
            "sites": "https://engineering.example.com",
            "pages": "https://docs.example.com/changes",
            "feeds": "https://news.example.com/feed.xml",
        },
        follow_redirects=False,
    )
    assert created.status_code == 303
    mission_path = next(
        (tmp_path / ".emerging-telemetry-research/missions").glob("*/mission.yaml")
    )
    mission = load_mission(mission_path)
    compiled = compile_mission(mission)
    assert compiled.collection_authorized is False
    assert [query.adapter for query in compiled.queries[-3:]] == [
        "brave_surface_search",
        "website_page",
        "rss_feed",
    ]

    page = client.get("/")
    assert page.status_code == 200
    assert "Exact source plan" in page.text
    assert "https://news.example.com/feed.xml" in page.text

    activated = client.post(
        f"/mission/{mission.mission_id}/activate",
        data={
            "csrf": csrf,
            "approved_by": "Research owner",
            "approval_id": "local-setup-test",
        },
        follow_redirects=False,
    )
    assert activated.status_code == 303
    active_path = mission_path.with_name("mission.active.yaml")
    assert compile_mission(load_mission(active_path)).collection_authorized is True

    scheduled = client.post(
        f"/mission/{mission.mission_id}/schedule",
        data={"csrf": csrf, "run_now": "true"},
        follow_redirects=False,
    )
    assert scheduled.status_code == 303
    assert (tmp_path / ".emerging-telemetry-research/schedules.db").is_file()
    assert "Portable scheduler" in client.get("/").text


def test_setup_rejects_missing_csrf_and_unsafe_host(tmp_path: Path) -> None:
    client = _client(tmp_path)
    _login(client)

    rejected = client.post(
        "/initialize",
        data={"profile": "portable"},
        follow_redirects=False,
    )
    assert rejected.status_code == 303
    assert "authenticity" in rejected.headers["location"]

    unsafe_host = client.get("/health", headers={"host": "attacker.example"})
    assert unsafe_host.status_code == 403


def test_setup_certifies_a_real_harness_only_after_cost_acknowledgement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status = HarnessStatus(
        harness="codex",
        available=True,
        version="test-version",
        authentication="unverified",
        detail="test harness",
        contract_test_required=True,
    )
    monkeypatch.setattr(setup_main, "harness_status", lambda adapter: status)
    monkeypatch.setattr(setup_main, "build_agent_provider", lambda adapter: object())

    async def evaluation(**kwargs: Any) -> dict[str, Any]:
        del kwargs
        return {"passed": True, "gates": {"all_roles_completed": True}}

    monkeypatch.setattr(setup_main, "run_agent_evaluation", evaluation)
    client = _client(tmp_path)
    _login(client)
    csrf = _csrf_value(TOKEN)

    rejected = client.post(
        "/harness-test",
        data={"csrf": csrf, "adapter": "codex"},
        follow_redirects=False,
    )
    assert rejected.status_code == 303
    assert "quota" in rejected.headers["location"]

    certified = client.post(
        "/harness-test",
        data={
            "csrf": csrf,
            "adapter": "codex",
            "acknowledge_cost": "true",
        },
        follow_redirects=False,
    )
    assert certified.status_code == 303
    assert (
        tmp_path / ".emerging-telemetry-research/harness-tests/codex.receipt.json"
    ).is_file()
