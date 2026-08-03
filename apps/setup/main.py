from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import re
import shutil
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from packages.agents.runtime import build_agent_provider
from packages.evaluation.agent_harness import run_agent_evaluation
from packages.missions.compiler import (
    activate_mission,
    add_web_source,
    compile_mission,
    draft_mission,
    load_mission,
    write_activation_receipt,
    write_mission,
)
from packages.missions.feedback import record_mission_feedback
from packages.onboarding.environment import load_environment_file
from packages.onboarding.harnesses import (
    harness_status,
    inspect_harnesses,
    write_harness_test_receipt,
)
from packages.onboarding.workspace import (
    CONFIG_DIRECTORY,
    configure_agent_runtime,
    configure_keyring_credential,
    initialize_workspace,
    run_doctor,
)
from packages.scheduler.runtime import MissionScheduleStore
from packages.security_gateway.deployment import (
    DeploymentApprovalError,
    DeploymentControlPaths,
    apply_approval_request,
    create_approval_request,
    require_deployment_approval,
    write_private_json,
    write_private_yaml,
)

SETUP_ROOT = Path(__file__).resolve().parent
SESSION_COOKIE = "etr_setup_session"
MISSION_ID_PATTERN = re.compile(r"^ms_[a-z0-9][a-z0-9_-]{2,63}$")
ALLOWED_SECRET_NAMES = {"BRAVE_API_KEY", "XAI_API_KEY", "ETR_AGENT_API_KEY"}
MAX_FORM_BYTES = 32_768


@dataclass(frozen=True, slots=True)
class SetupSettings:
    project_root: Path
    access_token: str
    profile: str = "portable"
    testing: bool = False

    def __post_init__(self) -> None:
        if len(self.access_token) < 24:
            raise ValueError("setup access token must contain at least 24 characters")
        if self.profile not in {"core", "portable", "production"}:
            raise ValueError("setup profile must be core, portable, or production")


def create_app(settings: SetupSettings) -> FastAPI:
    root = settings.project_root.resolve()
    templates = Environment(
        loader=FileSystemLoader(SETUP_ROOT / "templates"),
        autoescape=select_autoescape(("html", "xml")),
        undefined=StrictUndefined,
    )
    application = FastAPI(
        title="Emerging Telemetry Research setup",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.login_consumed = False
    application.mount("/static", StaticFiles(directory=SETUP_ROOT / "static"), name="static")

    @application.exception_handler(ValueError)
    async def rejected_form(request: Request, exc: ValueError) -> Response:
        del request
        return _redirect(error=str(exc))

    @application.middleware("http")
    async def setup_boundary(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not _loopback_client(request, testing=settings.testing) or not _safe_host(request):
            return Response(status_code=403)
        public = request.url.path in {"/login", "/health"} or request.url.path.startswith(
            "/static/"
        )
        if not public and not _authenticated(request, settings.access_token):
            return RedirectResponse("/login", status_code=303)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self' data:; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @application.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/login", response_class=HTMLResponse)
    async def login(request: Request, token: str = "") -> Response:
        if not application.state.login_consumed and hmac.compare_digest(
            token, settings.access_token
        ):
            application.state.login_consumed = True
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(
                SESSION_COOKIE,
                _session_value(settings.access_token),
                httponly=True,
                samesite="strict",
                secure=False,
                max_age=60 * 60,
            )
            return response
        document = templates.get_template("login.html").render(request=request)
        return HTMLResponse(document, status_code=401 if token else 200)

    @application.get("/", response_class=HTMLResponse)
    async def index(request: Request, notice: str = "", error: str = "") -> HTMLResponse:
        _reload_environment(root)
        snapshot = _snapshot(settings)
        document = templates.get_template("index.html").render(
            request=request,
            snapshot=snapshot,
            csrf=_csrf_value(settings.access_token),
            notice=notice[:300],
            error=error[:300],
        )
        return HTMLResponse(document)

    @application.post("/initialize")
    async def initialize(request: Request) -> Response:
        form = await _verified_form(request, settings.access_token)
        profile = form.get("profile", settings.profile)
        try:
            initialize_workspace(root, profile=profile)
            _reload_environment(root)
        except ValueError as exc:
            return _redirect(error=str(exc))
        return _redirect(notice="Private workspace initialized. Existing files were preserved.")

    @application.post("/agent")
    async def configure_agent(request: Request) -> Response:
        form = await _verified_form(request, settings.access_token)
        try:
            configure_agent_runtime(
                config_path=_config_path(root),
                adapter=form.get("adapter", "auto"),
                mode=form.get("mode", "plan"),
                model=form.get("model", ""),
                base_url=form.get("base_url", ""),
                provider_name=form.get("provider_name", ""),
            )
            _reload_environment(root)
        except ValueError as exc:
            return _redirect(error=str(exc))
        return _redirect(notice="Harness settings saved without exposing credentials.")

    @application.post("/harness-test")
    async def certify_harness(request: Request) -> Response:
        form = await _verified_form(request, settings.access_token)
        adapter = form.get("adapter", "")
        if form.get("acknowledge_cost") != "true":
            return _redirect(error="Acknowledge provider quota before testing a harness.")
        if adapter in {"", "auto", "fixture"}:
            return _redirect(error="Choose one real harness to certify.")
        status = harness_status(adapter)
        if status is None or not status.available:
            return _redirect(error=f"{adapter} is unavailable or not configured.")
        output = root / CONFIG_DIRECTORY / "harness-tests"
        try:
            evaluation = await run_agent_evaluation(
                fixtures_root=_fixture_root(),
                output_root=output / adapter / "evaluation",
                provider=build_agent_provider(adapter),
                adapter_name=adapter,
                repeats=1,
                case="early",
            )
            receipt = write_harness_test_receipt(
                output / f"{adapter}.receipt.json",
                status=status,
                evaluation=evaluation,
            )
        except (RuntimeError, ValueError) as exc:
            return _redirect(error=str(exc))
        return _redirect(
            notice=f"{adapter} passed the five-role contract test. Receipt: {receipt.name}."
        )

    @application.post("/secret")
    async def store_secret(request: Request) -> Response:
        form = await _verified_form(request, settings.access_token)
        name = form.get("name", "")
        value = form.get("value", "")
        if name not in ALLOWED_SECRET_NAMES or not value or len(value) > 16_384:
            return _redirect(error="Choose an allowed credential and provide a bounded value.")
        try:
            configure_keyring_credential(name, value, config_path=_config_path(root))
            _reload_environment(root)
        except ValueError as exc:
            return _redirect(error=str(exc))
        return _redirect(notice=f"{name} stored in the OS credential store.")

    @application.post("/deployment-approval")
    async def approve_collection(request: Request) -> Response:
        form = await _verified_form(request, settings.access_token)
        try:
            expires_days = int(form.get("expires_days", "30"))
            controls = _control_paths(root)
            approval_request = create_approval_request(
                environment_id=f"local:{root.name}",
                paths=controls,
            )
            approval = apply_approval_request(
                approval_request,
                approved_by=form.get("approved_by", ""),
                approval_id=form.get("approval_id", ""),
                expires_days=expires_days,
                paths=controls,
            )
            write_private_json(
                root / CONFIG_DIRECTORY / "deployment-approval-request.json",
                approval_request,
            )
            write_private_yaml(
                root / CONFIG_DIRECTORY / "deployment-approval.yaml",
                approval,
            )
        except (DeploymentApprovalError, ValueError) as exc:
            return _redirect(error=str(exc))
        return _redirect(
            notice=(
                "Collection approved for the reviewed controls. External delivery and "
                "self-improvement remain disabled."
            )
        )

    @application.post("/mission")
    async def create_mission(request: Request) -> Response:
        form = await _verified_form(request, settings.access_token)
        try:
            mission = draft_mission(
                form.get("objective", ""),
                name=form.get("name") or None,
                outcome_noun=form.get("result_type") or None,
                window_hours=int(form.get("window_hours", "168")),
                cadence=form.get("cadence", "daily"),
                workflow_template=form.get("workflow_template", "balanced"),
            )
            for url in _lines(form.get("sites", "")):
                mission = add_web_source(mission, url, kind="search")
            for url in _lines(form.get("pages", "")):
                mission = add_web_source(mission, url, kind="page")
            for url in _lines(form.get("feeds", "")):
                mission = add_web_source(mission, url, kind="rss")
            destination = _mission_root(root, mission.mission_id) / "mission.yaml"
            write_mission(mission, destination)
        except (TypeError, ValueError) as exc:
            return _redirect(error=str(exc))
        return _redirect(notice=f"Drafted {mission.name}. Review its exact source plan below.")

    @application.post("/mission/{mission_id}/source")
    async def add_source(request: Request, mission_id: str) -> Response:
        form = await _verified_form(request, settings.access_token)
        path = _draft_mission_path(root, mission_id)
        if path is None:
            return _redirect(error="Draft mission not found.")
        try:
            mission = add_web_source(
                load_mission(path),
                form.get("url", ""),
                kind=form.get("kind", "search"),
            )
            backup = path.with_name("mission.previous.yaml")
            shutil.copyfile(path, backup)
            write_mission(mission, path, force=True)
        except ValueError as exc:
            return _redirect(error=str(exc))
        return _redirect(notice="Source added in draft mode; live collection remains off.")

    @application.post("/mission/{mission_id}/activate")
    async def activate(request: Request, mission_id: str) -> Response:
        form = await _verified_form(request, settings.access_token)
        path = _draft_mission_path(root, mission_id)
        if path is None:
            return _redirect(error="Draft mission not found.")
        mission_root = path.parent
        try:
            activation = activate_mission(
                load_mission(path),
                approved_by=form.get("approved_by", ""),
                approval_id=form.get("approval_id", ""),
            )
            write_mission(activation.mission, mission_root / "mission.active.yaml")
            write_activation_receipt(
                activation.receipt,
                mission_root / "activation-receipt.json",
            )
        except ValueError as exc:
            return _redirect(error=str(exc))
        return _redirect(notice="Mission activated with a hash-bound rollback receipt.")

    @application.post("/mission/{mission_id}/report/{report_id}/feedback")
    async def feedback(request: Request, mission_id: str, report_id: str) -> Response:
        form = await _verified_form(request, settings.access_token)
        mission_path = _active_or_draft_mission_path(root, mission_id)
        report_path = _report_path(root, mission_id, report_id)
        if mission_path is None or report_path is None:
            return _redirect(error="Mission report not found.")
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            if not isinstance(report, dict):
                raise ValueError("mission report is invalid")
            record_mission_feedback(
                load_mission(mission_path),
                report,
                outcome_id=form.get("outcome_id", ""),
                label=form.get("label", ""),
                reason=form.get("reason", ""),
                submitted_by=form.get("submitted_by", ""),
                output_root=root / "reports/mission-feedback",
            )
        except (OSError, ValueError) as exc:
            return _redirect(error=str(exc))
        return _redirect(notice="Feedback recorded for the next evaluation cycle.")

    @application.post("/mission/{mission_id}/schedule")
    async def schedule(request: Request, mission_id: str) -> Response:
        form = await _verified_form(request, settings.access_token)
        mission_path = _active_or_draft_mission_path(root, mission_id)
        if mission_path is None or mission_path.name != "mission.active.yaml":
            return _redirect(error="Activate the mission before scheduling it.")
        try:
            MissionScheduleStore(_schedule_db(root)).add(
                mission_path,
                run_now=form.get("run_now") == "true",
            )
        except ValueError as exc:
            return _redirect(error=str(exc))
        return _redirect(
            notice=(
                "Mission scheduled. Run `uv run emerging-telemetry-research schedule serve` "
                "to start the portable worker."
            )
        )

    return application


def _snapshot(settings: SetupSettings) -> dict[str, Any]:
    root = settings.project_root.resolve()
    config = _config_path(root)
    selected_profile = os.environ.get("ETR_PROFILE", settings.profile).strip()
    if selected_profile not in {"core", "portable", "production"}:
        selected_profile = settings.profile
    controls = _control_paths(root)
    try:
        doctor = run_doctor(
            profile=selected_profile,
            config_path=config,
            control_paths=controls,
        )
    except ValueError as exc:
        doctor = {"ready": False, "checks": [], "error": str(exc)}
    try:
        approval_request = create_approval_request(
            environment_id=f"local:{root.name}",
            paths=controls,
        )
        try:
            approval = require_deployment_approval(
                "collection",
                approval_path=root / CONFIG_DIRECTORY / "deployment-approval.yaml",
                paths=controls,
            )
        except DeploymentApprovalError:
            approval = None
        deployment = {
            "available": True,
            "approved": approval is not None,
            "control_hash": approval_request["control_hash"],
            "source_ids": approval_request["source_ids"],
            "expires_at": approval.get("expires_at") if approval is not None else None,
        }
    except DeploymentApprovalError as exc:
        deployment = {
            "available": False,
            "approved": False,
            "error": str(exc),
            "source_ids": [],
        }
    missions: list[dict[str, Any]] = []
    mission_base = root / CONFIG_DIRECTORY / "missions"
    for path in sorted(mission_base.glob("*/mission.yaml")):
        try:
            mission = load_mission(path)
            compiled = compile_mission(mission)
        except (OSError, ValueError):
            continue
        active_path = path.with_name("mission.active.yaml")
        missions.append(
            {
                "mission_id": mission.mission_id,
                "name": mission.name,
                "objective": mission.objective,
                "path": str(path.relative_to(root)),
                "active": active_path.is_file(),
                "sources": mission.payload["sources"],
                "queries": compiled.manifest["query_plan"],
            }
        )
    reports: list[dict[str, Any]] = []
    for path in sorted((root / "reports/missions").glob("ms_*/*/report.json"), reverse=True):
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(report, dict) or not isinstance(report.get("outcomes"), list):
            continue
        reports.append(
            {
                "mission_id": str(report.get("mission_id", "")),
                "mission_name": str(report.get("mission_name", "")),
                "report_id": str(report.get("report_id", "")),
                "generated_at": str(report.get("generated_at", "")),
                "outcomes": [item for item in report["outcomes"] if isinstance(item, dict)],
            }
        )
        if len(reports) == 10:
            break
    schedules = (
        MissionScheduleStore(_schedule_db(root)).list()
        if _schedule_db(root).is_file()
        else ()
    )
    return {
        "profile": selected_profile,
        "workspace_initialized": config.is_file(),
        "config_path": str(config.relative_to(root)),
        "doctor": doctor,
        "deployment": deployment,
        "harnesses": [item.to_contract() for item in inspect_harnesses()],
        "missions": missions,
        "reports": reports,
        "schedules": [item.to_contract() for item in schedules],
    }


async def _verified_form(request: Request, token: str) -> dict[str, str]:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].lower()
    if content_type != "application/x-www-form-urlencoded":
        raise ValueError("setup forms require URL-encoded data")
    body = await request.body()
    if len(body) > MAX_FORM_BYTES:
        raise ValueError("setup form exceeds the size limit")
    values = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=40)
    form = {name: items[-1] for name, items in values.items() if items}
    if not hmac.compare_digest(form.get("csrf", ""), _csrf_value(token)):
        raise ValueError("setup form authenticity check failed")
    return form


def _reload_environment(root: Path) -> None:
    config = _config_path(root)
    if config.is_file():
        load_environment_file(config, override=True)


def _config_path(root: Path) -> Path:
    return root / CONFIG_DIRECTORY / "config.env"


def _schedule_db(root: Path) -> Path:
    return root / CONFIG_DIRECTORY / "schedules.db"


def _fixture_root() -> Path:
    installed = SETUP_ROOT.parents[1] / "fixtures" / "vertical_slice"
    if installed.is_dir():
        return installed
    source = SETUP_ROOT.parents[1] / "tests" / "fixtures" / "vertical_slice"
    if source.is_dir():
        return source
    raise ValueError("packaged harness-test fixtures are unavailable")


def _control_paths(root: Path) -> DeploymentControlPaths:
    config = root / CONFIG_DIRECTORY / "config"
    return DeploymentControlPaths(
        discovery=config / "discovery.yaml",
        sources=config / "sources.yaml",
        source_terms=config / "source-terms.yaml",
    )


def _mission_root(root: Path, mission_id: str) -> Path:
    if not MISSION_ID_PATTERN.fullmatch(mission_id):
        raise ValueError("mission ID is invalid")
    return root / CONFIG_DIRECTORY / "missions" / mission_id


def _draft_mission_path(root: Path, mission_id: str) -> Path | None:
    try:
        path = _mission_root(root, mission_id) / "mission.yaml"
    except ValueError:
        return None
    return path if path.is_file() else None


def _active_or_draft_mission_path(root: Path, mission_id: str) -> Path | None:
    draft = _draft_mission_path(root, mission_id)
    if draft is None:
        return None
    active = draft.with_name("mission.active.yaml")
    return active if active.is_file() else draft


def _report_path(root: Path, mission_id: str, report_id: str) -> Path | None:
    if not re.fullmatch(r"mr_[A-Za-z0-9_-]{3,100}", report_id):
        return None
    try:
        mission_directory = _mission_root(root, mission_id).name
    except ValueError:
        return None
    report = root / "reports/missions" / mission_directory / report_id / "report.json"
    return report if report.is_file() else None


def _lines(value: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in value.splitlines() if line.strip())


def _session_value(token: str) -> str:
    return hmac.new(token.encode(), b"etr-setup-session-v1", hashlib.sha256).hexdigest()


def _csrf_value(token: str) -> str:
    session = _session_value(token).encode()
    return hmac.new(token.encode(), b"etr-setup-csrf-v1:" + session, hashlib.sha256).hexdigest()


def _authenticated(request: Request, token: str) -> bool:
    return hmac.compare_digest(request.cookies.get(SESSION_COOKIE, ""), _session_value(token))


def _loopback_client(request: Request, *, testing: bool) -> bool:
    if request.client is None:
        return False
    if testing and request.client.host == "testclient":
        return True
    try:
        return ipaddress.ip_address(request.client.host).is_loopback
    except ValueError:
        return False


def _safe_host(request: Request) -> bool:
    host = request.headers.get("host", "")
    try:
        hostname = urlsplit("//" + host).hostname
    except ValueError:
        return False
    return hostname in {"127.0.0.1", "::1", "localhost", "testserver"}


def _redirect(*, notice: str = "", error: str = "") -> RedirectResponse:
    parameters = []
    if notice:
        parameters.append("notice=" + quote(notice[:300]))
    if error:
        parameters.append("error=" + quote(error[:300]))
    destination = "/" + ("?" + "&".join(parameters) if parameters else "")
    return RedirectResponse(destination, status_code=303)
