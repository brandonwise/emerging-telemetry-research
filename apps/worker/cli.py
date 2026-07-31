from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

import typer

from packages.agents.runtime import (
    AGENT_ADAPTERS,
    AGENT_MODES,
    AgentProvider,
    build_agent_provider,
)
from packages.analytics.store import AnalyticsStore
from packages.common.canonical import canonical_json_bytes
from packages.connectors.live import OfficialSourceClient
from packages.delivery.discord import build_discord_delivery_plan
from packages.delivery.email import (
    SmtpDeliverySettings,
    build_email_delivery_plan,
    send_email_delivery_plan,
)
from packages.discovery.clients import (
    BraveSearchClient,
    RedditSearchClient,
    TikTokResearchClient,
    XaiXSearchClient,
)
from packages.evaluation.agent_harness import run_agent_evaluation
from packages.evaluation.coverage_harness import evaluate_source_coverage
from packages.evaluation.harness import run_acceptance_suite
from packages.improvement.controller import (
    ALL_TAXONOMIES,
    apply_proposal,
    record_feedback,
    rollback_proposal,
    run_improvement_cycle,
)
from packages.inference.semantic import build_semantic_shadow_evaluator
from packages.onboarding.generator import (
    DEFAULT_TEMPLATES_ROOT,
    SUPPORTED_PLATFORMS,
    generate_setup,
)
from packages.pipeline.frozen import run_frozen_fixture
from packages.pipeline.live import LiveRunSettings, run_live_radar
from packages.storage.object_store import LocalImmutableObjectStore
from packages.storage.runtime import (
    ProductionStoreSettings,
    initialize_production_stores,
)
from packages.storage.sqlite import SQLiteRepository

DEFAULT_ANALYTICS_DB = Path(os.environ.get("RADAR_ANALYTICS_DB", "state/radar.db"))
DEFAULT_OBJECT_ROOT = Path(os.environ.get("RADAR_OBJECT_ROOT", "state/objects"))
DEFAULT_REPORT_ROOT = Path(os.environ.get("RADAR_REPORT_ROOT", "reports/generated"))
DEFAULT_EMBEDDINGS_CONFIG = Path(
    os.environ.get("RADAR_EMBEDDINGS_CONFIG", "config/embeddings.yaml")
)

app = typer.Typer(no_args_is_help=True)
run_app = typer.Typer(no_args_is_help=True)
fixture_app = typer.Typer(no_args_is_help=True)
report_app = typer.Typer(no_args_is_help=True)
eval_app = typer.Typer(no_args_is_help=True)
live_app = typer.Typer(no_args_is_help=True)
feedback_app = typer.Typer(no_args_is_help=True)
improve_app = typer.Typer(no_args_is_help=True)
portable_app = typer.Typer(no_args_is_help=True)
analytics_app = typer.Typer(no_args_is_help=True)
setup_app = typer.Typer(no_args_is_help=True)
app.add_typer(run_app, name="run")
app.add_typer(fixture_app, name="fixture")
app.add_typer(report_app, name="report")
app.add_typer(eval_app, name="eval")
app.add_typer(live_app, name="live")
app.add_typer(feedback_app, name="feedback")
app.add_typer(improve_app, name="improve")
app.add_typer(portable_app, name="portable")
app.add_typer(analytics_app, name="analytics")
app.add_typer(setup_app, name="setup")


def emit(payload: dict[str, Any], pretty: bool = False) -> None:
    if pretty:
        typer.echo(json.dumps(payload, indent=2, sort_keys=True))
    else:
        typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def read_stdin_json() -> dict[str, Any]:
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise typer.BadParameter("stdin must contain one JSON object")
    return value


@run_app.command("create")
def create_run(
    mode: str,
    edition: str = "none",
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    del json_output
    emit(
        {
            "run_id": f"run_{uuid4().hex}",
            "mode": mode,
            "edition": edition,
            "status": "planned",
            "collection_enabled": False,
            "created_at": datetime.now(UTC).isoformat(),
        }
    )


@fixture_app.command("run")
def fixture_run(
    manifest: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True),
    ],
    output: Annotated[Path, typer.Option("--output")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    result = run_frozen_fixture(manifest, output)
    emit(
        {
            "run_id": json.loads(manifest.read_text(encoding="utf-8"))["run_id"],
            "report_id": result.report["report_id"],
            "report_json": str(result.report_json_path.resolve()),
            "report_html": str(result.rendered.path.resolve()),
            "audit_log": str(result.audit_path.resolve()),
            "report_json_hash": result.rendered.report_json_hash,
            "rendered_html_hash": result.rendered.rendered_html_hash,
            "publication_class": result.report["findings"][0]["publication_class"],
            "priority_score": result.report["findings"][0]["priority_score"],
            "external_delivery": "disabled",
        },
        pretty=not json_output,
    )


@live_app.command("run")
def live_run(
    output: Annotated[Path, typer.Option("--output")] = Path("reports/generated"),
    edition: Annotated[str, typer.Option("--edition")] = "morning",
    analytics_db: Annotated[Path, typer.Option("--analytics-db")] = DEFAULT_ANALYTICS_DB,
    email_recipient: Annotated[str | None, typer.Option("--email-recipient")] = (
        os.environ.get("RADAR_EMAIL_RECIPIENT") or None
    ),
    agent_mode: Annotated[str, typer.Option("--agent-mode")] = os.environ.get(
        "RADAR_AGENT_MODE", "plan"
    ),
    agent_adapter: Annotated[str, typer.Option("--agent-adapter")] = os.environ.get(
        "RADAR_AGENT_ADAPTER", "openclaw"
    ),
    agent_concurrency: Annotated[int, typer.Option("--agent-concurrency", min=1, max=8)] = 3,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if edition not in {"morning", "afternoon_delta", "weekly", "flash"}:
        raise typer.BadParameter("unsupported live edition")
    stores = initialize_production_stores(
        ProductionStoreSettings(
            database_url=_required_env("RADAR_DATABASE_URL"),
            s3_endpoint_url=_required_env("RADAR_S3_ENDPOINT_URL"),
            s3_access_key_id=_required_env("RADAR_S3_ACCESS_KEY_ID"),
            s3_secret_access_key=_required_env("RADAR_S3_SECRET_ACCESS_KEY"),
            s3_bucket=_required_env("RADAR_S3_BUCKET"),
            s3_region=os.environ.get("RADAR_S3_REGION", "us-east-1"),
            server_side_encryption=_s3_encryption_mode(),
        ),
        migrations_root=Path("migrations"),
    )
    provider = _agent_runtime(agent_mode, agent_adapter)
    result = asyncio.run(
        run_live_radar(
            LiveRunSettings(
                output_root=output,
                discord_channel_id=None,
                email_recipient=email_recipient,
                edition=edition,
                agent_mode=agent_mode,
                agent_max_concurrency=agent_concurrency,
            ),
            brave_client=BraveSearchClient(_required_env("BRAVE_API_KEY")),
            x_search_client=XaiXSearchClient(_required_env("XAI_API_KEY")),
            reddit_client=_optional_reddit_client(),
            tiktok_client=_optional_tiktok_client(),
            official_client=OfficialSourceClient(),
            object_store=stores.object_store,
            repository=stores.repository,
            semantic_evaluator=build_semantic_shadow_evaluator(DEFAULT_EMBEDDINGS_CONFIG),
            agent_provider=provider,
        )
    )
    indexed = AnalyticsStore(analytics_db).index_path(result.report_json_path)
    emit(
        {
            "run_id": result.run_id,
            "report_id": result.report["report_id"],
            "report_json": str(result.report_json_path.resolve()),
            "html_path": str(result.rendered.path.resolve()),
            "delivery_plan": str(result.delivery_plan_path.resolve()),
            "delivery_destination": result.delivery_plan["destination"],
            "candidate_cves": list(result.candidate_cves),
            "emerging_signal_count": result.emerging_signal_count,
            "qualified_emerging_count": result.qualified_emerging_count,
            "source_native_signal_count": result.source_native_signal_count,
            "discovery_telemetry": result.report.get("discovery_telemetry"),
            "semantic_shadow": result.semantic_shadow,
            "agent_mode": agent_mode,
            "agent_review_count": len(result.report.get("agent_reviews", [])),
            "degraded_sources": list(result.degraded_sources),
            "analytics_db": str(analytics_db.resolve()),
            "analytics_indexed": indexed.inserted,
            "external_delivery": "disabled",
        },
        pretty=not json_output,
    )


@portable_app.command("run")
def portable_run(
    output: Annotated[Path, typer.Option("--output")] = Path("reports/generated"),
    database: Annotated[Path, typer.Option("--database")] = DEFAULT_ANALYTICS_DB,
    objects: Annotated[Path, typer.Option("--objects")] = DEFAULT_OBJECT_ROOT,
    edition: Annotated[str, typer.Option("--edition")] = "morning",
    agent_mode: Annotated[str, typer.Option("--agent-mode")] = os.environ.get(
        "RADAR_AGENT_MODE", "plan"
    ),
    agent_adapter: Annotated[str, typer.Option("--agent-adapter")] = os.environ.get(
        "RADAR_AGENT_ADAPTER", "codex"
    ),
    agent_concurrency: Annotated[int, typer.Option("--agent-concurrency", min=1, max=8)] = 3,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run live discovery with SQLite, local immutable objects, and no external delivery."""
    if edition not in {"morning", "afternoon_delta", "weekly", "flash"}:
        raise typer.BadParameter("unsupported live edition")
    provider = _agent_runtime(agent_mode, agent_adapter)
    result = asyncio.run(
        run_live_radar(
            LiveRunSettings(
                output_root=output,
                discord_channel_id=None,
                edition=edition,
                agent_mode=agent_mode,
                agent_max_concurrency=agent_concurrency,
            ),
            brave_client=BraveSearchClient(_required_env("BRAVE_API_KEY")),
            x_search_client=XaiXSearchClient(_required_env("XAI_API_KEY")),
            reddit_client=_optional_reddit_client(),
            tiktok_client=_optional_tiktok_client(),
            official_client=OfficialSourceClient(),
            object_store=LocalImmutableObjectStore(objects),
            repository=SQLiteRepository(database),
            semantic_evaluator=build_semantic_shadow_evaluator(DEFAULT_EMBEDDINGS_CONFIG),
            agent_provider=provider,
        )
    )
    indexed = AnalyticsStore(database).index_path(result.report_json_path)
    emit(
        {
            "run_id": result.run_id,
            "report_id": result.report["report_id"],
            "finding_count": len(result.report["findings"]),
            "report_json": str(result.report_json_path.resolve()),
            "html_path": str(result.rendered.path.resolve()),
            "delivery_plan": str(result.delivery_plan_path.resolve()),
            "delivery_destination": result.delivery_plan["destination"],
            "candidate_cves": list(result.candidate_cves),
            "emerging_signal_count": result.emerging_signal_count,
            "qualified_emerging_count": result.qualified_emerging_count,
            "source_native_signal_count": result.source_native_signal_count,
            "discovery_telemetry": result.report.get("discovery_telemetry"),
            "semantic_shadow": result.semantic_shadow,
            "agent_mode": agent_mode,
            "agent_review_count": len(result.report.get("agent_reviews", [])),
            "degraded_sources": list(result.degraded_sources),
            "analytics_db": str(database.resolve()),
            "analytics_indexed": indexed.inserted,
            "external_delivery": "disabled",
        },
        pretty=not json_output,
    )


@analytics_app.command("sync")
def analytics_sync(
    reports: Annotated[Path, typer.Option("--reports")] = Path("reports/generated"),
    database: Annotated[Path, typer.Option("--database")] = DEFAULT_ANALYTICS_DB,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Index or rebuild trend data from immutable report JSON."""
    result = AnalyticsStore(database).sync_reports(reports)
    emit(
        {
            **result,
            "database": str(database.resolve()),
            "reports_root": str(reports.resolve()),
        },
        pretty=not json_output,
    )


@analytics_app.command("overview")
def analytics_overview(
    database: Annotated[Path, typer.Option("--database")] = DEFAULT_ANALYTICS_DB,
    days: Annotated[int, typer.Option("--days", min=1, max=3650)] = 30,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Print aggregate report, finding, source-health, usage, and cost metrics."""
    emit(AnalyticsStore(database).overview(days=days), pretty=not json_output)


@analytics_app.command("event")
def analytics_event(
    metric: str,
    value: float,
    unit: str,
    dimensions_json: Annotated[str, typer.Option("--dimensions-json")] = "{}",
    run_id: Annotated[str | None, typer.Option("--run-id")] = None,
    database: Annotated[Path, typer.Option("--database")] = DEFAULT_ANALYTICS_DB,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Record one bounded, content-free operational telemetry event."""
    dimensions = json.loads(dimensions_json)
    if not isinstance(dimensions, dict) or not all(
        isinstance(key, str) and isinstance(item, str) for key, item in dimensions.items()
    ):
        raise typer.BadParameter("dimensions must be a JSON object of string values")
    event_id = AnalyticsStore(database).record_event(
        metric=metric,
        value=value,
        unit=unit,
        dimensions=dimensions,
        run_id=run_id,
    )
    emit(
        {"event_id": event_id, "status": "recorded"},
        pretty=not json_output,
    )


@analytics_app.command("events")
def analytics_events(
    database: Annotated[Path, typer.Option("--database")] = DEFAULT_ANALYTICS_DB,
    days: Annotated[int, typer.Option("--days", min=1, max=3650)] = 30,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Print grouped operational telemetry for reporting and trend analysis."""
    emit(
        {
            "days": days,
            "metrics": AnalyticsStore(database).event_summary(days=days),
        },
        pretty=not json_output,
    )


@setup_app.command("generate")
def setup_generate(
    platform: Annotated[str, typer.Option("--platform")],
    output: Annotated[Path, typer.Option("--output")] = Path("."),
    force: Annotated[bool, typer.Option("--force")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Generate a safe OpenClaw, Claude Code, Codex, or generic project adapter."""
    if platform not in SUPPORTED_PLATFORMS:
        raise typer.BadParameter("platform must be one of: " + ", ".join(SUPPORTED_PLATFORMS))
    try:
        result = generate_setup(
            platform=platform,
            output_root=output,
            templates_root=DEFAULT_TEMPLATES_ROOT,
            force=force,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "platform": result.platform,
            "output_root": str(result.output_root),
            "files": [str(path) for path in result.files],
            "next": [
                "copy radar.env.example to radar.env",
                "configure BRAVE_API_KEY and XAI_API_KEY in a secret store",
                "run ./run-radar.sh",
            ],
        },
        pretty=not json_output,
    )


def _s3_encryption_mode() -> str | None:
    value = os.environ.get("RADAR_S3_SERVER_SIDE_ENCRYPTION", "AES256")
    if value == "AES256":
        return value
    if value == "none":
        return None
    raise typer.BadParameter("RADAR_S3_SERVER_SIDE_ENCRYPTION must be AES256 or none")


def _agent_runtime(mode: str, adapter: str) -> AgentProvider | None:
    if mode not in AGENT_MODES:
        raise typer.BadParameter("agent mode must be one of: " + ", ".join(AGENT_MODES))
    if mode == "plan":
        return None
    if adapter not in AGENT_ADAPTERS:
        raise typer.BadParameter("agent adapter must be one of: " + ", ".join(AGENT_ADAPTERS))
    try:
        return build_agent_provider(adapter)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc


@report_app.command("delivery-plan")
def delivery_plan(
    report_json: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True),
    ],
    html_path: Annotated[
        Path,
        typer.Option("--html", exists=True, dir_okay=False, readable=True),
    ],
    channel_id: Annotated[str, typer.Option("--channel-id")],
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    value = json.loads(report_json.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise typer.BadParameter("report JSON must be an object")
    plan = build_discord_delivery_plan(
        value,
        html_path=html_path,
        channel_id=channel_id,
    )
    encoded = canonical_json_bytes(plan) + b"\n"
    if output:
        if output.exists() and output.read_bytes() != encoded:
            raise typer.BadParameter("refusing to overwrite a different delivery plan")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not output.exists():
            with output.open("xb") as handle:
                handle.write(encoded)
    emit(plan, pretty=True)


@report_app.command("email-plan")
def email_delivery_plan(
    report_json: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True),
    ],
    html_path: Annotated[
        Path,
        typer.Option("--html", exists=True, dir_okay=False, readable=True),
    ],
    recipient: Annotated[str | None, typer.Option("--recipient")] = (
        os.environ.get("RADAR_EMAIL_RECIPIENT") or None
    ),
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    if recipient is None:
        raise typer.BadParameter("email recipient is required")
    value = json.loads(report_json.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise typer.BadParameter("report JSON must be an object")
    try:
        plan = build_email_delivery_plan(
            value,
            html_path=html_path,
            recipient=recipient,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    encoded = canonical_json_bytes(plan) + b"\n"
    if output:
        if output.exists() and output.read_bytes() != encoded:
            raise typer.BadParameter("refusing to overwrite a different delivery plan")
        output.parent.mkdir(parents=True, exist_ok=True)
        if not output.exists():
            with output.open("xb") as handle:
                handle.write(encoded)
    emit(plan, pretty=True)


@report_app.command("email-send")
def email_send(
    plan_path: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True),
    ],
    report_root: Annotated[Path, typer.Option("--report-root")] = DEFAULT_REPORT_ROOT,
) -> None:
    if os.environ.get("EXTERNAL_DELIVERY_ENABLED", "").lower() != "true":
        raise typer.BadParameter("external delivery is disabled")
    if os.environ.get("RADAR_EMAIL_DELIVERY_ENABLED", "").lower() != "true":
        raise typer.BadParameter("email delivery is disabled")
    try:
        receipt = send_email_delivery_plan(
            plan_path,
            report_root=report_root,
            settings=SmtpDeliverySettings.from_env(),
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(receipt, pretty=True)


@report_app.command("deliver")
def deliver_report() -> None:
    if os.environ.get("EXTERNAL_DELIVERY_ENABLED", "").lower() != "true":
        raise typer.BadParameter("external delivery is disabled")
    raise typer.BadParameter(
        "direct CLI delivery is forbidden; use the reviewed radar_delivery_send OpenClaw tool"
    )


@eval_app.command("acceptance")
def eval_acceptance(
    output: Annotated[Path, typer.Option("--output")],
    fixtures: Annotated[
        Path,
        typer.Option(
            "--fixtures",
            exists=True,
            file_okay=False,
            readable=True,
        ),
    ] = Path("tests/fixtures/vertical_slice"),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    result = run_acceptance_suite(fixtures, output)
    emit(result, pretty=not json_output)
    if result["passed"] is not True:
        raise typer.Exit(code=1)


@eval_app.command("agents")
def eval_agents(
    output: Annotated[Path, typer.Option("--output")] = Path("reports/generated/agent-evaluation"),
    fixtures: Annotated[
        Path,
        typer.Option(
            "--fixtures",
            exists=True,
            file_okay=False,
            readable=True,
        ),
    ] = Path("tests/fixtures/vertical_slice"),
    adapter: Annotated[str, typer.Option("--adapter")] = os.environ.get(
        "RADAR_AGENT_ADAPTER", "fixture"
    ),
    case: Annotated[str | None, typer.Option("--case")] = None,
    repeats: Annotated[int, typer.Option("--repeats", min=1, max=10)] = 3,
    maximum_mean_duration_ms: Annotated[
        int, typer.Option("--maximum-mean-duration-ms", min=1)
    ] = 300_000,
    maximum_mean_tokens: Annotated[int, typer.Option("--maximum-mean-tokens", min=1)] = 100_000,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run the bounded agent DAG repeatedly and report quality, cost, and stability."""
    if adapter not in AGENT_ADAPTERS:
        raise typer.BadParameter("agent adapter must be one of: " + ", ".join(AGENT_ADAPTERS))
    try:
        provider = build_agent_provider(adapter)
        result = asyncio.run(
            run_agent_evaluation(
                fixtures_root=fixtures,
                output_root=output,
                provider=provider,
                adapter_name=adapter,
                repeats=repeats,
                case=case,
                maximum_mean_review_duration_ms=maximum_mean_duration_ms,
                maximum_mean_review_tokens=maximum_mean_tokens,
            )
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(result, pretty=not json_output)
    if result["passed"] is not True:
        raise typer.Exit(code=1)


@eval_app.command("coverage")
def eval_coverage(
    reports: Annotated[Path, typer.Option("--reports")] = Path("reports/generated"),
    output: Annotated[Path, typer.Option("--output")] = Path("reports/generated/source-evaluation"),
    minimum_surfaces: Annotated[int, typer.Option("--minimum-surfaces", min=1, max=20)] = 4,
    maximum_surface_share: Annotated[
        float, typer.Option("--maximum-surface-share", min=0.01, max=1.0)
    ] = 0.6,
    maximum_x_share: Annotated[float, typer.Option("--maximum-x-share", min=0.0, max=1.0)] = 0.5,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Measure source diversity, attribution, and X concentration in generated reports."""
    result = evaluate_source_coverage(
        reports_root=reports,
        output_root=output,
        minimum_surface_count=minimum_surfaces,
        maximum_single_surface_share=maximum_surface_share,
        maximum_x_share=maximum_x_share,
    )
    emit(result, pretty=not json_output)
    if result["passed"] is not True:
        raise typer.Exit(code=1)


@feedback_app.command("record")
def feedback_record(
    report_json: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True),
    ],
    finding_id: str,
    taxonomy: str,
    submitted_by: Annotated[str, typer.Option("--submitted-by")],
    output: Annotated[Path, typer.Option("--output")] = Path("reports/feedback"),
    analytics_db: Annotated[Path, typer.Option("--analytics-db")] = DEFAULT_ANALYTICS_DB,
    notes: Annotated[str | None, typer.Option("--notes")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if taxonomy not in ALL_TAXONOMIES:
        raise typer.BadParameter("taxonomy must be one of: " + ", ".join(sorted(ALL_TAXONOMIES)))
    feedback, path = record_feedback(
        report_path=report_json,
        finding_id=finding_id,
        taxonomy=taxonomy,
        submitted_by=submitted_by,
        output_root=output,
        notes=notes,
    )
    AnalyticsStore(analytics_db).record_event(
        metric="feedback.recorded",
        value=1,
        unit="label",
        occurred_at=str(feedback["created_at"]),
        dimensions={
            "report_id": str(feedback["report_id"]),
            "finding_id": str(feedback["finding_id"]),
            "taxonomy": str(feedback["taxonomy"]),
        },
    )
    emit(
        {
            "feedback_id": feedback["feedback_id"],
            "feedback_path": str(path.resolve()),
            "status": "recorded",
        },
        pretty=not json_output,
    )


@improve_app.command("analyze")
def improve_analyze(
    reports: Annotated[Path, typer.Option("--reports")] = Path("reports/generated"),
    feedback: Annotated[Path, typer.Option("--feedback")] = Path("reports/feedback"),
    output: Annotated[Path, typer.Option("--output")] = Path("reports/generated/improvement"),
    fixtures: Annotated[
        Path,
        typer.Option("--fixtures", exists=True, file_okay=False, readable=True),
    ] = Path("tests/fixtures/vertical_slice"),
    scoring_config: Annotated[
        Path,
        typer.Option(
            "--scoring-config",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = Path("config/scoring.yaml"),
    improvement_config: Annotated[
        Path,
        typer.Option(
            "--improvement-config",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = Path("config/improvement.yaml"),
    analytics_db: Annotated[Path, typer.Option("--analytics-db")] = DEFAULT_ANALYTICS_DB,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    result = run_improvement_cycle(
        reports_root=reports,
        feedback_root=feedback,
        output_root=output,
        fixture_root=fixtures,
        scoring_config=scoring_config,
        improvement_config=improvement_config,
    )
    AnalyticsStore(analytics_db).record_event(
        metric="improvement.cycle",
        value=1,
        unit="cycle",
        occurred_at=str(result["generated_at"]),
        run_id=str(result["cycle_id"]),
        dimensions={
            "status": str(result["status"]),
            "proposal_created": str(result["proposal_id"] is not None).lower(),
            "acceptance_passed": str(result["anchors"]["acceptance_passed"]).lower(),
        },
    )
    emit(result, pretty=not json_output)


@improve_app.command("apply")
def improve_apply(
    proposal: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True),
    ],
    approved_by: Annotated[str, typer.Option("--approved-by")],
    approval_id: Annotated[str, typer.Option("--approval-id")],
    repo_root: Annotated[
        Path,
        typer.Option("--repo-root", exists=True, file_okay=False, writable=True),
    ] = Path("."),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    result = apply_proposal(
        proposal,
        repo_root=repo_root,
        approved_by=approved_by,
        approval_id=approval_id,
    )
    emit(result, pretty=not json_output)


@improve_app.command("apply-stdin")
def improve_apply_stdin(
    approved_by: Annotated[str, typer.Option("--approved-by")],
    approval_id: Annotated[str, typer.Option("--approval-id")],
    repo_root: Annotated[
        Path,
        typer.Option("--repo-root", exists=True, file_okay=False, writable=True),
    ] = Path("."),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    payload = read_stdin_json()
    proposal_path = payload.get("proposal_path")
    if payload.get("status") != "approval_required" or not isinstance(proposal_path, str):
        raise typer.BadParameter("stdin does not contain an approval-ready proposal")
    result = apply_proposal(
        Path(proposal_path),
        repo_root=repo_root,
        approved_by=approved_by,
        approval_id=approval_id,
    )
    emit(result, pretty=not json_output)


@improve_app.command("rollback")
def improve_rollback(
    receipt: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True),
    ],
    approved_by: Annotated[str, typer.Option("--approved-by")],
    approval_id: Annotated[str, typer.Option("--approval-id")],
    repo_root: Annotated[
        Path,
        typer.Option("--repo-root", exists=True, file_okay=False, writable=True),
    ] = Path("."),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    result = rollback_proposal(
        receipt,
        repo_root=repo_root,
        approved_by=approved_by,
        approval_id=approval_id,
    )
    emit(result, pretty=not json_output)


@run_app.command("blocked-live-collection")
def blocked_live_collection() -> None:
    payload = read_stdin_json()
    emit(
        {
            **payload,
            "status": "blocked",
            "reason": "threat_model_and_source_collection_approval_required",
        }
    )
    raise typer.Exit(code=2)


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise typer.BadParameter(f"{name} is required")
    return value


def _optional_reddit_client() -> RedditSearchClient | None:
    access_token = os.environ.get("REDDIT_ACCESS_TOKEN")
    user_agent = os.environ.get("REDDIT_USER_AGENT")
    if not access_token or not user_agent:
        return None
    return RedditSearchClient(access_token, user_agent=user_agent)


def _optional_tiktok_client() -> TikTokResearchClient | None:
    access_token = os.environ.get("TIKTOK_RESEARCH_ACCESS_TOKEN")
    if not access_token:
        return None
    return TikTokResearchClient(access_token)


if __name__ == "__main__":
    app()
