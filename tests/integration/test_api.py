import json
from pathlib import Path

import yaml
from fastapi.testclient import TestClient
from jsonschema import Draft202012Validator

from apps.api.main import ApiSettings, create_app
from packages.pipeline.frozen import run_frozen_fixture
from packages.storage.repository import MemoryRepository

FINGERPRINT = "a" * 64
IDEMPOTENCY_KEY = "b" * 32


def client_for(role: str, tmp_path: Path, repo: MemoryRepository | None = None) -> TestClient:
    settings = ApiSettings(
        mtls_identities_json=json.dumps({FINGERPRINT: role}),
        report_root=tmp_path,
        external_delivery_enabled=False,
    )
    return TestClient(
        create_app(
            settings=settings,
            repository=repo or MemoryRepository(),
        ),
        client=("127.0.0.1", 41000),
    )


def test_api_fails_closed_without_mtls_identity_map(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            settings=ApiSettings(mtls_identities_json="{}", report_root=tmp_path),
            repository=MemoryRepository(),
        ),
        client=("127.0.0.1", 41000),
    )
    response = client.get("/v1/health")
    assert response.status_code == 503
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_api_rejects_certificate_headers_from_untrusted_proxy(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            settings=ApiSettings(
                mtls_identities_json=json.dumps({FINGERPRINT: "operator"}),
                report_root=tmp_path,
            ),
            repository=MemoryRepository(),
        ),
        client=("203.0.113.10", 41000),
    )
    response = client.get(
        "/v1/health",
        headers={"X-Client-Cert-SHA256": FINGERPRINT},
    )
    assert response.status_code == 401


def test_role_and_unknown_field_checks(tmp_path: Path) -> None:
    collector = client_for("collector", tmp_path)
    denied = collector.post(
        "/v1/runs",
        headers={
            "X-Client-Cert-SHA256": FINGERPRINT,
            "Idempotency-Key": IDEMPOTENCY_KEY,
        },
        json={
            "mode": "shadow",
            "edition": "morning",
            "scheduled_for": "2026-07-22T12:00:00Z",
            "code_revision": "1234567",
            "policy_revision": "v1",
        },
    )
    assert denied.status_code == 403

    orchestrator = client_for("orchestrator", tmp_path)
    invalid = orchestrator.post(
        "/v1/runs",
        headers={
            "X-Client-Cert-SHA256": FINGERPRINT,
            "Idempotency-Key": IDEMPOTENCY_KEY,
        },
        json={
            "mode": "shadow",
            "edition": "morning",
            "scheduled_for": "2026-07-22T12:00:00Z",
            "code_revision": "1234567",
            "policy_revision": "v1",
            "unknown": "rejected",
        },
    )
    assert invalid.status_code == 400


def test_run_creation_is_retry_safe_and_conflicts_on_payload_change(tmp_path: Path) -> None:
    repository = MemoryRepository()
    orchestrator = client_for("orchestrator", tmp_path, repository)
    headers = {
        "X-Client-Cert-SHA256": FINGERPRINT,
        "Idempotency-Key": IDEMPOTENCY_KEY,
    }
    payload = {
        "mode": "shadow",
        "edition": "morning",
        "scheduled_for": "2026-07-22T12:00:00Z",
        "code_revision": "1234567",
        "policy_revision": "v1",
    }
    first = orchestrator.post("/v1/runs", headers=headers, json=payload)
    replay = orchestrator.post("/v1/runs", headers=headers, json=payload)
    assert first.status_code == 201
    assert replay.status_code == 201
    assert replay.json() == first.json()
    contract = yaml.safe_load(Path("openapi/openapi.yaml").read_text(encoding="utf-8"))
    Draft202012Validator(contract["components"]["schemas"]["Run"]).validate(first.json())

    conflict_payload = {**payload, "edition": "weekly"}
    conflict = orchestrator.post("/v1/runs", headers=headers, json=conflict_payload)
    assert conflict.status_code == 409


def test_verified_report_renders_but_delivery_stays_disabled(tmp_path: Path) -> None:
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        tmp_path / "fixture",
    )
    repository = MemoryRepository()
    publisher = client_for("publisher", tmp_path / "rendered", repository)
    headers = {
        "X-Client-Cert-SHA256": FINGERPRINT,
        "Idempotency-Key": IDEMPOTENCY_KEY,
    }
    rendered = publisher.post("/v1/reports/render", headers=headers, json=result.report)
    assert rendered.status_code == 200
    assert Path(rendered.json()["html_path"]).is_file()

    from packages.delivery.discord import build_discord_delivery_plan

    plan = build_discord_delivery_plan(
        result.report,
        html_path=result.rendered.path,
        channel_id="1476283808587321451",
    )
    blocked = publisher.post(
        "/v1/deliveries",
        headers={
            "X-Client-Cert-SHA256": FINGERPRINT,
            "Idempotency-Key": "c" * 32,
        },
        json=plan,
    )
    assert blocked.status_code == 409
