import hmac
import ipaddress
import json
import re
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from apps.report_renderer.render import render_report
from packages.agents.contracts import validate_assessment
from packages.common.canonical import canonical_json_bytes, stable_id
from packages.contracts.validation import ContractViolation, validate_payload
from packages.storage.repository import (
    IdempotencyConflict,
    PostgresRepository,
    RadarRepository,
    RepositoryUnavailable,
    UnavailableRepository,
)

FINGERPRINT = re.compile(r"^[a-f0-9]{64}$")
IDEMPOTENCY = re.compile(r"^[A-Za-z0-9_-]{32,128}$")


class ApiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RADAR_API_", extra="ignore")

    mtls_identities_json: str = "{}"
    report_root: Path = Path("reports/generated")
    external_delivery_enabled: bool = False
    database_url: str | None = None
    trusted_proxy_ips_json: str = '["127.0.0.1", "::1"]'

    def identity_roles(self) -> dict[str, str]:
        value = json.loads(self.mtls_identities_json)
        if not isinstance(value, dict):
            raise ValueError("mTLS identity map must be an object")
        result: dict[str, str] = {}
        for fingerprint, role in value.items():
            normalized = str(fingerprint).lower()
            if not FINGERPRINT.fullmatch(normalized):
                raise ValueError("mTLS fingerprint must be 64 lowercase hex characters")
            result[normalized] = str(role)
        return result

    def trusted_proxy_ips(self) -> set[str]:
        value = json.loads(self.trusted_proxy_ips_json)
        if not isinstance(value, list) or not value:
            raise ValueError("trusted proxy IPs must be a non-empty array")
        return {str(ipaddress.ip_address(str(item))) for item in value}


class ClosedModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class CreateRunRequest(ClosedModel):
    mode: str = Field(min_length=1, max_length=100)
    edition: str = Field(pattern=r"^(none|flash|morning|afternoon_delta|weekly)$")
    scheduled_for: datetime
    code_revision: str = Field(min_length=7, max_length=64)
    policy_revision: str = Field(min_length=1, max_length=100)


class ArtifactSubmission(ClosedModel):
    run_id: str = Field(pattern=r"^run_[A-Za-z0-9_-]+$")
    source_id: str = Field(min_length=1, max_length=100)
    canonical_uri: str = Field(pattern=r"^https://")
    retrieved_at: datetime
    published_at: datetime | None = None
    content_type: str = Field(min_length=1, max_length=200)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    object_key: str = Field(min_length=1, max_length=1000)


def create_app(
    *,
    settings: ApiSettings | None = None,
    repository: RadarRepository | None = None,
) -> FastAPI:
    api_settings = settings or ApiSettings()
    repo: RadarRepository = repository or (
        PostgresRepository(api_settings.database_url)
        if api_settings.database_url
        else UnavailableRepository()
    )
    application = FastAPI(
        title="OpenClaw Emerging Threat Radar internal API",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.settings = api_settings
    application.state.repository = repo

    @application.middleware("http")
    async def security_headers(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @application.exception_handler(RequestValidationError)
    async def invalid_request_handler(_request: Any, _exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "invalid request"},
        )

    @application.exception_handler(ContractViolation)
    async def contract_handler(_request: Any, exc: ContractViolation) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": str(exc)},
        )

    @application.exception_handler(IdempotencyConflict)
    async def idempotency_handler(_request: Any, exc: IdempotencyConflict) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content={"detail": str(exc)},
        )

    @application.exception_handler(RepositoryUnavailable)
    async def repository_handler(_request: Any, _exc: RepositoryUnavailable) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"detail": "repository unavailable"},
        )

    @application.get("/v1/health")
    async def health(
        _role: Annotated[str, Depends(_authorize(api_settings, {"operator", "orchestrator"}))],
    ) -> dict[str, Any]:
        if not await repo.available():
            raise HTTPException(status_code=503, detail="repository unavailable")
        return {
            "status": "ok",
            "collection_enabled": False,
            "external_delivery_enabled": api_settings.external_delivery_enabled,
        }

    @application.post("/v1/runs", status_code=status.HTTP_201_CREATED)
    async def create_run(
        request: CreateRunRequest,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        _role: Annotated[str, Depends(_authorize(api_settings, {"orchestrator"}))],
    ) -> dict[str, Any]:
        _validate_idempotency_key(idempotency_key)
        payload = request.model_dump(mode="json")
        run_id = stable_id("run", idempotency_key)
        record = {
            "run_id": run_id,
            **payload,
            "status": "planned",
            "created_at": datetime.now(UTC).isoformat(),
        }
        return await repo.put_idempotent(
            "runs",
            idempotency_key,
            payload,
            run_id,
            record,
        )

    @application.post("/v1/artifacts", status_code=status.HTTP_202_ACCEPTED)
    async def submit_artifact(
        request: ArtifactSubmission,
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        _role: Annotated[str, Depends(_authorize(api_settings, {"collector"}))],
    ) -> dict[str, Any]:
        _validate_idempotency_key(idempotency_key)
        payload = request.model_dump(mode="json")
        artifact_id = stable_id("ra", request.source_id, request.content_hash)
        record = {"artifact_id": artifact_id, **payload}
        await repo.put_idempotent(
            "artifacts",
            idempotency_key,
            payload,
            artifact_id,
            record,
        )
        return {"artifact_id": artifact_id, "status": "quarantined"}

    @application.post("/v1/observations", status_code=status.HTTP_202_ACCEPTED)
    async def submit_observation(
        payload: Annotated[dict[str, Any], Body()],
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        _role: Annotated[str, Depends(_authorize(api_settings, {"extractor"}))],
    ) -> dict[str, Any]:
        _validate_idempotency_key(idempotency_key)
        validate_payload("observation.schema.json", payload)
        observation_id = str(payload["observation_id"])
        await repo.put_idempotent(
            "observations",
            idempotency_key,
            payload,
            observation_id,
            payload,
        )
        return {"observation_id": observation_id, "status": "accepted"}

    @application.post("/v1/assessments", status_code=status.HTTP_202_ACCEPTED)
    async def submit_assessment(
        payload: Annotated[dict[str, Any], Body()],
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        _role: Annotated[
            str,
            Depends(
                _authorize(
                    api_settings,
                    {"specialist", "impact", "skeptic", "citation_verifier", "coordinator"},
                )
            ),
        ],
    ) -> dict[str, Any]:
        _validate_idempotency_key(idempotency_key)
        validate_assessment(payload, await repo.evidence_ids())
        assessment_id = str(payload["assessment_id"])
        await repo.put_idempotent(
            "assessments",
            idempotency_key,
            payload,
            assessment_id,
            payload,
        )
        return {"assessment_id": assessment_id, "status": "accepted"}

    @application.get("/v1/evidence/{evidence_id}")
    async def get_evidence(
        evidence_id: str,
        _role: Annotated[
            str,
            Depends(
                _authorize(
                    api_settings,
                    {"specialist", "impact", "skeptic", "citation_verifier", "coordinator"},
                )
            ),
        ],
    ) -> dict[str, Any]:
        if not re.fullmatch(r"ev_[A-Za-z0-9_-]+", evidence_id):
            raise HTTPException(status_code=400, detail="invalid evidence ID")
        evidence = await repo.get("evidence", evidence_id)
        if evidence is None:
            raise HTTPException(status_code=404, detail="evidence not found")
        return evidence

    @application.post("/v1/reports/render")
    async def render(
        payload: Annotated[dict[str, Any], Body()],
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        _role: Annotated[str, Depends(_authorize(api_settings, {"publisher"}))],
    ) -> dict[str, Any]:
        _validate_idempotency_key(idempotency_key)
        validate_payload("report.schema.json", payload)
        report_id = str(payload["report_id"])
        _write_immutable(
            api_settings.report_root / f"{report_id}.json",
            canonical_json_bytes(payload) + b"\n",
        )
        rendered = render_report(payload, api_settings.report_root / f"{report_id}.html")
        record = {
            "report_id": report_id,
            "report_json_hash": rendered.report_json_hash,
            "rendered_html_hash": rendered.rendered_html_hash,
            "html_path": str(rendered.path.resolve()),
        }
        return await repo.put_idempotent(
            "reports",
            idempotency_key,
            payload,
            report_id,
            record,
        )

    @application.post("/v1/deliveries", status_code=status.HTTP_202_ACCEPTED)
    async def submit_delivery(
        payload: Annotated[dict[str, Any], Body()],
        idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
        _role: Annotated[str, Depends(_authorize(api_settings, {"publisher"}))],
    ) -> dict[str, Any]:
        _validate_idempotency_key(idempotency_key)
        validate_payload("delivery.schema.json", payload)
        if not api_settings.external_delivery_enabled:
            raise HTTPException(status_code=409, detail="external delivery is disabled")
        delivery_id = str(payload["delivery_id"])
        await repo.put_idempotent(
            "deliveries",
            idempotency_key,
            payload,
            delivery_id,
            payload,
        )
        return {"delivery_id": delivery_id, "status": "pending"}

    @application.get("/v1/source-health")
    async def source_health(
        _role: Annotated[str, Depends(_authorize(api_settings, {"operator", "orchestrator"}))],
    ) -> list[dict[str, Any]]:
        return await repo.source_health_records()

    @application.get("/v1/runs/{run_id}/usage")
    async def run_usage(
        run_id: str,
        _role: Annotated[str, Depends(_authorize(api_settings, {"operator", "orchestrator"}))],
    ) -> list[dict[str, Any]]:
        if not re.fullmatch(r"run_[A-Za-z0-9_-]+", run_id):
            raise HTTPException(status_code=400, detail="invalid run ID")
        return await repo.usage_records(run_id)

    return application


class RoleAuthorizer:
    def __init__(self, settings: ApiSettings, allowed_roles: set[str]) -> None:
        self._settings = settings
        self._allowed_roles = frozenset(allowed_roles)

    async def __call__(self, request: Request) -> str:
        client_host = request.client.host if request.client else ""
        try:
            normalized_client = str(ipaddress.ip_address(client_host))
        except ValueError as exc:
            raise HTTPException(
                status_code=401,
                detail="request did not arrive via mTLS proxy",
            ) from exc
        if normalized_client not in self._settings.trusted_proxy_ips():
            raise HTTPException(status_code=401, detail="request did not arrive via mTLS proxy")
        identities = self._settings.identity_roles()
        if not identities:
            raise HTTPException(status_code=503, detail="mTLS identity map is not configured")
        normalized = request.headers.get("x-client-cert-sha256", "").lower()
        matched_role = next(
            (
                role
                for expected, role in identities.items()
                if hmac.compare_digest(expected, normalized)
            ),
            None,
        )
        if matched_role is None:
            raise HTTPException(status_code=401, detail="client identity is not authorized")
        if matched_role not in self._allowed_roles:
            raise HTTPException(status_code=403, detail="client role is not authorized")
        return matched_role


def _authorize(settings: ApiSettings, allowed_roles: set[str]) -> RoleAuthorizer:
    return RoleAuthorizer(settings, allowed_roles)


def _validate_idempotency_key(value: str) -> None:
    if not IDEMPOTENCY.fullmatch(value):
        raise HTTPException(status_code=400, detail="invalid idempotency key")


def _write_immutable(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() != content:
            raise HTTPException(status_code=409, detail="immutable output conflict")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(content)


app = create_app()
