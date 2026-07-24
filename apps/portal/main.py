from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import io
import ipaddress
import json
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qs

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

PORTAL_ROOT = Path(__file__).resolve().parent
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


class PortalSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="RADAR_PORTAL_", extra="ignore")

    analytics_db: Path = Path("state/radar.db")
    reports_root: Path = Path("reports/generated")
    lan_mode: bool = False
    auth_mode: Literal["auto", "required", "disabled"] = "auto"
    access_token: str | None = None
    secure_cookie: bool = False
    allowed_networks: str = (
        "127.0.0.0/8,::1/128,10.0.0.0/8,172.16.0.0/12,"
        "192.168.0.0/16,fc00::/7"
    )
    title: str = Field(default="Threat Radar", min_length=1, max_length=80)

    @model_validator(mode="after")
    def validate_lan_auth(self) -> PortalSettings:
        authentication_required = self.auth_mode == "required" or (
            self.auth_mode == "auto" and self.lan_mode
        )
        if authentication_required and (
            self.access_token is None or len(self.access_token) < 20
        ):
            raise ValueError(
                "This authentication mode requires RADAR_PORTAL_ACCESS_TOKEN "
                "with 20+ characters"
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
        return _render(
            templates,
            "dashboard.html",
            request=request,
            settings=portal_settings,
            active="overview",
            overview=store.overview(days=bounded_days),
            trend=store.daily_trend(days=bounded_days),
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
            edition
            if edition in {"flash", "morning", "afternoon_delta", "weekly"}
            else None
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
            trend=trend,
            max_findings=max((int(item["findings"]) for item in trend), default=1),
            source_health=store.source_health(),
            events=store.event_summary(days=bounded_days),
            taxonomy=store.taxonomy_counts(days=bounded_days),
            days=bounded_days,
        )

    @application.get("/setup", response_class=HTMLResponse)
    async def setup(request: Request) -> HTMLResponse:
        return _render(
            templates,
            "setup.html",
            request=request,
            settings=portal_settings,
            active="setup",
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
            export_row["source_types"] = "|".join(
                str(item) for item in row.get("source_types", [])
            )
            writer.writerow(
                {
                    key: _safe_csv(export_row.get(key))
                    for key in CSV_FINDING_FIELDS
                }
            )
        return Response(
            output.getvalue(),
            media_type="text/csv; charset=utf-8",
            headers={
                "Content-Disposition": 'attachment; filename="threat-radar-findings.csv"'
            },
        )

    @application.get("/exports/findings.json")
    async def export_findings_json() -> Response:
        return Response(
            json.dumps(store.export_finding_rows(), indent=2, sort_keys=True),
            media_type="application/json",
            headers={
                "Content-Disposition": 'attachment; filename="threat-radar-findings.json"'
            },
        )

    @application.get("/exports/reports/{report_id}.json")
    async def export_report_json(report_id: str) -> Response:
        report = store.get_report(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        return Response(
            json.dumps(report, indent=2, sort_keys=True),
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="{report_id}.json"'
            },
        )

    @application.get("/exports/reports/{report_id}.html")
    async def export_report_html(report_id: str) -> FileResponse:
        rows = [
            row for row in store.list_reports(limit=500) if row["report_id"] == report_id
        ]
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


def _compact_date(value: object) -> str:
    text = str(value)
    return text[:10] if len(text) >= 10 else text


app = create_app()
