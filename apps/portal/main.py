from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import re
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
    Response,
)
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from packages.analytics.store import AnalyticsStore
from packages.contracts.validation import validate_payload
from packages.missions.compiler import (
    BUILTIN_MISSIONS_ROOT,
    compile_mission,
    draft_mission,
    load_mission,
)

PORTAL_ROOT = Path(__file__).resolve().parent
DOCUMENTS_ROOT = PORTAL_ROOT.parents[1] / "docs"
ARCHITECTURE_MOTION_PATH = DOCUMENTS_ROOT / "architecture-motion.html"
ARCHITECTURE_BLUEPRINT_PATH = DOCUMENTS_ROOT / "architecture-visual.html"
MISSION_ENGINE_PATH = DOCUMENTS_ROOT / "mission-engine.html"
ARCHITECTURE_GIF_PATH = DOCUMENTS_ROOT / "assets" / "threat-radar-architecture-motion.gif"
SESSION_COOKIE = "radar_session"
SESSION_SECONDS = 12 * 60 * 60
CSV_FIELDS = (
    "report_id",
    "generated_at",
    "edition",
    "finding_count",
    "max_score",
    "degraded_source_count",
    "estimated_cost",
)
CSV_FINDING_FIELDS = (
    "generated_at",
    "report_id",
    "finding_id",
    "title",
    "category",
    "tags",
    "source_types",
    "emergence_stage",
    "publication_class",
    "priority_score",
    "confidence_level",
    "confidence_probability",
)
MISSION_ID_PATTERN = re.compile(r"^ms_[a-z0-9][a-z0-9_-]{2,63}$")


def _inline_style_hash(document: str) -> str:
    _, start, remainder = document.partition("<style>")
    stylesheet, end, _ = remainder.partition("</style>")
    if not start or not end:
        raise ValueError("Architecture document has no inline stylesheet")
    digest = hashlib.sha256(stylesheet.encode("utf-8")).digest()
    return base64.b64encode(digest).decode("ascii")


class PortalSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RADAR_PORTAL_", extra="ignore")

    analytics_db: Path = Path("state/radar.db")
    reports_root: Path = Path("reports/generated")
    missions_root: Path = BUILTIN_MISSIONS_ROOT
    mission_reports_root: Path = Path("reports/missions")
    lan_mode: bool = False
    auth_mode: Literal["auto", "required", "disabled"] = "auto"
    access_token: str | None = None
    secure_cookie: bool = False
    allowed_networks: str = "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7"
    title: str = Field(default="Outcome Radar", min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_lan_auth(self) -> PortalSettings:
        authentication_required = self.auth_mode == "required" or (
            self.auth_mode == "auto" and self.lan_mode
        )
        if authentication_required and (self.access_token is None or len(self.access_token) < 20):
            raise ValueError(
                "This authentication mode requires RADAR_PORTAL_ACCESS_TOKEN with 20+ characters"
            )
        if (
            self.auth_mode != "disabled"
            and self.access_token is not None
            and len(self.access_token) < 20
        ):
            raise ValueError("RADAR_PORTAL_ACCESS_TOKEN must have 20+ characters")
        return self

    @property
    def authentication_enabled(self) -> bool:
        if self.auth_mode == "disabled":
            return False
        if self.auth_mode == "required":
            return True
        return self.access_token is not None

    def effective_access_token(self) -> str | None:
        return self.access_token if self.authentication_enabled else None

    def networks(self) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
        return tuple(
            ipaddress.ip_network(item.strip(), strict=True)
            for item in self.allowed_networks.split(",")
            if item.strip()
        )


def create_app(settings: PortalSettings | None = None) -> FastAPI:
    portal_settings = settings or PortalSettings()
    access_token = portal_settings.effective_access_token()
    store = AnalyticsStore(portal_settings.analytics_db)
    store.sync_reports(portal_settings.reports_root)
    templates = _templates()
    architecture_documents = {
        "/architecture": ARCHITECTURE_MOTION_PATH,
        "/architecture/blueprint": ARCHITECTURE_BLUEPRINT_PATH,
        "/architecture/missions": MISSION_ENGINE_PATH,
    }
    application = FastAPI(
        title=f"{portal_settings.title} portal",
        version="1.0.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    application.state.settings = portal_settings
    application.state.store = store
    application.mount(
        "/static",
        StaticFiles(directory=PORTAL_ROOT / "static"),
        name="static",
    )

    @application.middleware("http")
    async def portal_boundary(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not _client_allowed(request, portal_settings):
            return Response(status_code=403)
        public_path = request.url.path in {"/login", "/health"} or request.url.path.startswith(
            "/static/"
        )
        if (
            not public_path
            and access_token is not None
            and not _valid_session(request, access_token)
        ):
            if request.url.path.startswith("/exports/"):
                return JSONResponse({"detail": "authentication required"}, status_code=401)
            return RedirectResponse("/login", status_code=303)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        architecture_document = architecture_documents.get(request.url.path)
        if architecture_document is not None:
            architecture_style_hash = _inline_style_hash(
                architecture_document.read_text(encoding="utf-8")
            )
            response.headers["Content-Security-Policy"] = (
                f"default-src 'none'; style-src 'sha256-{architecture_style_hash}'; "
                "img-src data:; "
                "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
            )
        else:
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; style-src 'self'; img-src 'self' data:; "
                "font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
            )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @application.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/login", response_class=HTMLResponse)
    async def login_page(request: Request) -> Response:
        if access_token is None:
            return RedirectResponse("/", status_code=303)
        return _render(
            templates,
            "login.html",
            request=request,
            settings=portal_settings,
            error=None,
        )

    @application.post("/login", response_class=HTMLResponse)
    async def login(request: Request) -> Response:
        if access_token is None:
            return RedirectResponse("/", status_code=303)
        body = (await request.body()).decode("utf-8", errors="replace")
        supplied = parse_qs(body, strict_parsing=False).get("token", [""])[0]
        if not hmac.compare_digest(supplied, access_token):
            return _render(
                templates,
                "login.html",
                request=request,
                settings=portal_settings,
                error="That access token is not valid.",
                status_code=401,
            )
        response = RedirectResponse("/", status_code=303)
        response.set_cookie(
            SESSION_COOKIE,
            _session_value(access_token),
            max_age=SESSION_SECONDS,
            httponly=True,
            secure=portal_settings.secure_cookie,
            samesite="strict",
            path="/",
        )
        return response

    @application.post("/logout")
    async def logout() -> RedirectResponse:
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(SESSION_COOKIE, path="/")
        return response

    @application.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request, days: int = 30) -> HTMLResponse:
        bounded_days = max(7, min(days, 365))
        trend = store.daily_trend(days=bounded_days)
        priority_findings = _unique_findings(
            store.list_findings(
                limit=500,
                days=bounded_days,
                priority_first=True,
            ),
            limit=8,
        )
        return _render(
            templates,
            "dashboard.html",
            request=request,
            settings=portal_settings,
            active="overview",
            overview=store.overview(days=bounded_days),
            intelligence=store.intelligence_summary(days=bounded_days),
            source_posture=_source_posture(store.source_health(limit=500)),
            trend=trend,
            max_findings=max((int(item["findings"]) for item in trend), default=1),
            findings=priority_findings,
            reports=store.list_reports(limit=6),
            days=bounded_days,
        )

    @application.get("/reports", response_class=HTMLResponse)
    async def reports(
        request: Request,
        q: str | None = None,
        edition: str | None = None,
    ) -> HTMLResponse:
        safe_query = q.strip()[:120] if q else None
        safe_edition = (
            edition if edition in {"flash", "morning", "afternoon_delta", "weekly"} else None
        )
        return _render(
            templates,
            "reports.html",
            request=request,
            settings=portal_settings,
            active="reports",
            reports=store.list_reports(
                limit=200,
                edition=safe_edition,
                query=safe_query,
            ),
            q=safe_query or "",
            edition=safe_edition or "",
        )

    @application.get("/missions", response_class=HTMLResponse)
    async def missions(request: Request) -> HTMLResponse:
        return _render(
            templates,
            "missions.html",
            request=request,
            settings=portal_settings,
            active="missions",
            missions=_mission_cards(
                portal_settings.missions_root,
                portal_settings.mission_reports_root,
            ),
        )

    @application.get("/missions/new", response_class=HTMLResponse)
    async def mission_new(
        request: Request,
        objective: str | None = None,
        name: str | None = None,
        outcome: str | None = None,
        window_hours: int = 168,
        cadence: str = "daily",
    ) -> HTMLResponse:
        preview: dict[str, Any] | None = None
        error: str | None = None
        safe_objective = objective.strip()[:1200] if objective else ""
        safe_name = name.strip()[:100] if name else ""
        safe_outcome = outcome.strip()[:40] if outcome else ""
        bounded_window = max(1, min(window_hours, 2160))
        safe_cadence = cadence if cadence in {"manual", "hourly", "daily", "weekly"} else "daily"
        if safe_objective:
            try:
                mission = draft_mission(
                    safe_objective,
                    name=safe_name or None,
                    outcome_noun=safe_outcome or None,
                    window_hours=bounded_window,
                    cadence=safe_cadence,
                )
                preview = compile_mission(mission).to_contract()
            except ValueError as exc:
                error = str(exc)
        return _render(
            templates,
            "mission_new.html",
            request=request,
            settings=portal_settings,
            active="missions",
            objective=safe_objective,
            mission_name=safe_name,
            outcome=safe_outcome,
            window_hours=bounded_window,
            cadence=safe_cadence,
            preview=preview,
            error=error,
        )

    @application.get("/missions/download")
    async def mission_download(
        objective: str,
        name: str | None = None,
        outcome: str | None = None,
        window_hours: int = 168,
        cadence: str = "daily",
    ) -> Response:
        try:
            mission = draft_mission(
                objective.strip()[:1200],
                name=name.strip()[:100] if name else None,
                outcome_noun=outcome.strip()[:40] if outcome else None,
                window_hours=max(1, min(window_hours, 2160)),
                cadence=cadence,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        document = yaml.safe_dump(mission.to_contract(), sort_keys=False, allow_unicode=True)
        filename = mission.mission_id.removeprefix("ms_") + ".mission.yaml"
        return Response(
            document,
            media_type="application/yaml",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @application.get("/missions/{mission_id}/reports/{report_id}", response_class=HTMLResponse)
    async def mission_report_detail(
        request: Request,
        mission_id: str,
        report_id: str,
    ) -> HTMLResponse:
        path = _mission_report_path(
            portal_settings.mission_reports_root,
            mission_id,
            report_id,
        )
        if path is None:
            raise HTTPException(status_code=404, detail="mission report not found")
        report = _read_mission_report(path)
        if not report:
            raise HTTPException(status_code=404, detail="mission report not found")
        return _render(
            templates,
            "mission_report.html",
            request=request,
            settings=portal_settings,
            active="missions",
            report=report,
        )

    @application.get("/missions/{mission_id}", response_class=HTMLResponse)
    async def mission_detail(request: Request, mission_id: str) -> HTMLResponse:
        item = _mission_by_id(
            portal_settings.missions_root,
            portal_settings.mission_reports_root,
            mission_id,
        )
        if item is None:
            raise HTTPException(status_code=404, detail="mission not found")
        return _render(
            templates,
            "mission_detail.html",
            request=request,
            settings=portal_settings,
            active="missions",
            mission=item,
        )

    @application.get("/findings", response_class=HTMLResponse)
    async def findings(
        request: Request,
        q: str | None = None,
        category: str | None = None,
        tag: str | None = None,
        source: str | None = None,
    ) -> HTMLResponse:
        safe_query = q.strip()[:120] if q else None
        options = store.taxonomy_options()
        safe_category = category if category in options["categories"] else None
        safe_tag = tag if tag in options["tags"] else None
        safe_source = source if source in options["source_types"] else None
        return _render(
            templates,
            "findings.html",
            request=request,
            settings=portal_settings,
            active="findings",
            findings=store.list_findings(
                limit=500,
                query=safe_query,
                category=safe_category,
                tag=safe_tag,
                source_type=safe_source,
            ),
            options=options,
            q=safe_query or "",
            category=safe_category or "",
            tag=safe_tag or "",
            source=safe_source or "",
        )

    @application.get("/reports/{report_id}", response_class=HTMLResponse)
    async def report_detail(request: Request, report_id: str) -> HTMLResponse:
        report = store.get_report(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        return _render(
            templates,
            "report_detail.html",
            request=request,
            settings=portal_settings,
            active="reports",
            report=report,
        )

    @application.get("/trends", response_class=HTMLResponse)
    async def trends(request: Request, days: int = 90) -> HTMLResponse:
        bounded_days = max(7, min(days, 365))
        trend = store.daily_trend(days=bounded_days)
        return _render(
            templates,
            "trends.html",
            request=request,
            settings=portal_settings,
            active="trends",
            overview=store.overview(days=bounded_days),
            intelligence=store.intelligence_summary(days=bounded_days),
            trend=trend,
            max_findings=max((int(item["findings"]) for item in trend), default=1),
            source_health=store.source_health(),
            events=store.event_summary(days=bounded_days),
            taxonomy=store.taxonomy_counts(days=bounded_days),
            days=bounded_days,
        )

    @application.get("/setup", response_class=HTMLResponse)
    async def setup(request: Request, days: int = 30) -> HTMLResponse:
        bounded_days = max(7, min(days, 365))
        return _render(
            templates,
            "setup.html",
            request=request,
            settings=portal_settings,
            active="setup",
            costs=store.cost_breakdown(days=bounded_days),
            local_inference=store.local_inference_status(),
            days=bounded_days,
        )

    @application.get("/architecture", response_class=HTMLResponse)
    async def architecture() -> HTMLResponse:
        document = ARCHITECTURE_MOTION_PATH.read_text(encoding="utf-8")
        document = document.replace(
            '<div class="hero-actions">',
            '<div class="hero-actions"><a href="/">Return to command center ↙</a>',
            1,
        )
        document = document.replace(
            'href="architecture-visual.html"',
            'href="/architecture/blueprint"',
        )
        document = document.replace(
            'href="assets/threat-radar-architecture-motion.gif"',
            'href="/exports/architecture.gif"',
        )
        return HTMLResponse(document)

    @application.get("/architecture/blueprint", response_class=HTMLResponse)
    async def architecture_blueprint() -> HTMLResponse:
        document = ARCHITECTURE_BLUEPRINT_PATH.read_text(encoding="utf-8")
        document = document.replace(
            "<ol>",
            '<ol><li><a href="/">← Command center</a></li>',
            1,
        )
        document = document.replace(
            'href="architecture-motion.html"',
            'href="/architecture"',
        )
        return HTMLResponse(document)

    @application.get("/architecture/missions", response_class=HTMLResponse)
    async def mission_architecture() -> HTMLResponse:
        document = MISSION_ENGINE_PATH.read_text(encoding="utf-8")
        document = document.replace(
            'href="../README.md"',
            'href="/missions"',
        )
        return HTMLResponse(document)

    @application.get("/exports/architecture.gif")
    async def export_architecture_gif() -> FileResponse:
        return FileResponse(
            ARCHITECTURE_GIF_PATH,
            media_type="image/gif",
            filename="threat-radar-architecture-motion.gif",
        )

    @application.get("/exports/reports.csv")
    async def export_csv() -> Response:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS, extrasaction="ignore")
        writer.writeheader()
        for row in store.export_rows():
            writer.writerow({key: _safe_csv(row.get(key)) for key in CSV_FIELDS})
        return Response(
            output.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="threat-radar-reports.csv"'},
        )

    @application.get("/exports/reports.json")
    async def export_json() -> Response:
        return Response(
            json.dumps(store.export_rows(), indent=2, sort_keys=True),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="threat-radar-reports.json"'},
        )

    @application.get("/exports/findings.csv")
    async def export_findings_csv() -> Response:
        output = io.StringIO()
        writer = csv.DictWriter(
            output,
            fieldnames=CSV_FINDING_FIELDS,
            extrasaction="ignore",
        )
        writer.writeheader()
        for row in store.export_finding_rows():
            export_row = dict(row)
            export_row["tags"] = "|".join(str(item) for item in row.get("tags", []))
            export_row["source_types"] = "|".join(str(item) for item in row.get("source_types", []))
            writer.writerow({key: _safe_csv(export_row.get(key)) for key in CSV_FINDING_FIELDS})
        return Response(
            output.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="threat-radar-findings.csv"'},
        )

    @application.get("/exports/findings.json")
    async def export_findings_json() -> Response:
        return Response(
            json.dumps(store.export_finding_rows(), indent=2, sort_keys=True),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="threat-radar-findings.json"'},
        )

    @application.get("/exports/reports/{report_id}.json")
    async def export_report_json(report_id: str) -> Response:
        report = store.get_report(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        return Response(
            json.dumps(report, indent=2, sort_keys=True),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{report_id}.json"'},
        )

    @application.get("/exports/reports/{report_id}.html")
    async def export_report_html(report_id: str) -> FileResponse:
        rows = [row for row in store.list_reports(limit=500) if row["report_id"] == report_id]
        if not rows or not rows[0].get("html_path"):
            raise HTTPException(status_code=404, detail="HTML report not found")
        path = Path(str(rows[0]["html_path"])).resolve()
        if not path.is_file() or path.name != f"{report_id}.html":
            raise HTTPException(status_code=404, detail="HTML report not found")
        return FileResponse(
            path,
            media_type="text/html",
            filename=f"{report_id}.html",
        )

    return application


def _templates() -> Environment:
    environment = Environment(
        loader=FileSystemLoader(PORTAL_ROOT / "templates"),
        autoescape=select_autoescape(enabled_extensions=("html", "j2"), default=True),
        undefined=StrictUndefined,
    )
    environment.filters["compact_date"] = _compact_date
    environment.filters["money"] = lambda value: f"${float(value):,.4f}"
    environment.filters["compact_number"] = _compact_number
    environment.filters["duration"] = _duration
    return environment


def _render(
    environment: Environment,
    template_name: str,
    *,
    status_code: int = 200,
    **context: Any,
) -> HTMLResponse:
    return HTMLResponse(
        environment.get_template(template_name).render(**context),
        status_code=status_code,
    )


def _client_allowed(request: Request, settings: PortalSettings) -> bool:
    client = request.client
    if client is None:
        return False
    try:
        address = ipaddress.ip_address(client.host)
    except ValueError:
        return False
    if settings.lan_mode:
        return any(address in network for network in settings.networks())
    return address.is_loopback


def _session_value(token: str) -> str:
    expires = str(int(time.time()) + SESSION_SECONDS)
    signature = hmac.new(
        hashlib.sha256(token.encode("utf-8")).digest(),
        expires.encode("ascii"),
        hashlib.sha256,
    ).digest()
    encoded = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{expires}.{encoded}"


def _valid_session(request: Request, token: str) -> bool:
    value = request.cookies.get(SESSION_COOKIE, "")
    try:
        expires, supplied = value.split(".", 1)
        if int(expires) < int(time.time()):
            return False
    except (TypeError, ValueError):
        return False
    expected = _session_value_for_expiry(token, expires)
    return hmac.compare_digest(supplied, expected)


def _session_value_for_expiry(token: str, expires: str) -> str:
    signature = hmac.new(
        hashlib.sha256(token.encode("utf-8")).digest(),
        expires.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")


def _safe_csv(value: object) -> object:
    if isinstance(value, str) and value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value


def _unique_findings(
    rows: list[dict[str, Any]],
    *,
    limit: int,
) -> list[dict[str, Any]]:
    unique: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        finding_id = str(row["finding_id"])
        if finding_id in seen:
            continue
        seen.add(finding_id)
        unique.append(row)
        if len(unique) >= limit:
            break
    return unique


def _compact_date(value: object) -> str:
    text = str(value)
    return text[:10] if len(text) >= 10 else text


def _compact_number(value: object) -> str:
    try:
        number = float(str(value))
    except ValueError:
        number = 0.0
    if abs(number) >= 1_000_000:
        return f"{number / 1_000_000:.1f}M"
    if abs(number) >= 1_000:
        return f"{number / 1_000:.1f}K"
    return f"{number:,.0f}"


def _duration(value: object) -> str:
    try:
        milliseconds = max(0, int(float(str(value))))
    except ValueError:
        milliseconds = 0
    if milliseconds >= 60_000:
        return f"{milliseconds / 60_000:.1f} min"
    if milliseconds >= 1_000:
        return f"{milliseconds / 1_000:.1f} sec"
    return f"{milliseconds} ms"


def _source_posture(rows: list[dict[str, Any]]) -> dict[str, Any]:
    latest: list[dict[str, Any]] = []
    seen: set[str] = set()
    for row in rows:
        source_id = str(row["source_id"])
        if source_id in seen:
            continue
        seen.add(source_id)
        latest.append(row)
    healthy = sum(1 for row in latest if row["status"] == "healthy")
    return {
        "sources": latest,
        "healthy": healthy,
        "degraded": len(latest) - healthy,
        "total": len(latest),
        "health_rate": round(healthy / len(latest) * 100, 1) if latest else 0.0,
    }


def _mission_cards(missions_root: Path, reports_root: Path) -> list[dict[str, Any]]:
    cards: list[dict[str, Any]] = []
    if not missions_root.is_dir():
        return cards
    seen: set[str] = set()
    for path in sorted(missions_root.glob("**/mission*.yaml")):
        try:
            mission = load_mission(path)
            compiled = compile_mission(mission)
        except (OSError, ValueError):
            continue
        if mission.mission_id in seen:
            continue
        seen.add(mission.mission_id)
        report_paths = _mission_report_paths(reports_root, mission.mission_id)
        cards.append(
            {
                "definition": mission.to_contract(),
                "compiled": compiled.to_contract(),
                "path": path,
                "reports": [_read_mission_report(item) for item in report_paths],
            }
        )
    return cards


def _mission_by_id(
    missions_root: Path,
    reports_root: Path,
    mission_id: str,
) -> dict[str, Any] | None:
    if not _valid_mission_id(mission_id):
        return None
    return next(
        (
            item
            for item in _mission_cards(missions_root, reports_root)
            if item["definition"]["mission_id"] == mission_id
        ),
        None,
    )


def _mission_report_paths(root: Path, mission_id: str) -> list[Path]:
    mission_root = (root / mission_id).resolve()
    if root.resolve() not in mission_root.parents or not mission_root.is_dir():
        return []
    return sorted(mission_root.glob("*/report.json"), reverse=True)[:100]


def _mission_report_path(root: Path, mission_id: str, report_id: str) -> Path | None:
    if not _valid_mission_id(mission_id) or not report_id.startswith("mr_"):
        return None
    candidate = (root / mission_id / report_id / "report.json").resolve()
    if root.resolve() not in candidate.parents or not candidate.is_file():
        return None
    return candidate


def _read_mission_report(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            return {}
        validate_payload("mission-report.schema.json", value)
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    return value


def _valid_mission_id(value: str) -> bool:
    return MISSION_ID_PATTERN.fullmatch(value) is not None


app = create_app()
