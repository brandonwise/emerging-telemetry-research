from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import UTC, datetime
from decimal import Decimal
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
from packages.common.resources import configured_path
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
from packages.improvement.advisor import run_advisory_cycle
from packages.improvement.controller import (
    ALL_TAXONOMIES,
    apply_proposal,
    record_feedback,
    rollback_proposal,
    run_improvement_cycle,
)
from packages.inference.semantic import build_semantic_shadow_evaluator
from packages.missions.compiler import (
    BUILTIN_MISSIONS_ROOT,
    activate_mission,
    compile_mission,
    draft_mission,
    load_mission,
    rollback_mission,
    write_activation_receipt,
    write_mission,
)
from packages.missions.evaluation import evaluate_mission_report
from packages.missions.feedback import load_mission_feedback, record_mission_feedback
from packages.missions.runtime import collect_mission_signals, run_mission
from packages.onboarding.environment import load_environment_file
from packages.onboarding.generator import (
    DEFAULT_TEMPLATES_ROOT,
    SUPPORTED_PLATFORMS,
    generate_setup,
)
from packages.onboarding.workspace import (
    configure_keyring_credential,
    initialize_workspace,
    run_doctor,
)
from packages.pipeline.frozen import run_frozen_fixture
from packages.pipeline.live import LiveRunSettings, run_live_research
from packages.security_gateway.deployment import (
    DeploymentApprovalError,
    DeploymentControlPaths,
    apply_approval_request,
    create_approval_request,
    require_deployment_approval,
    write_private_json,
    write_private_yaml,
)
from packages.security_gateway.secrets import (
    SecretResolutionError,
    keyring_reference,
    resolve_secret,
)
from packages.storage.object_store import LocalImmutableObjectStore
from packages.storage.runtime import (
    ProductionStoreSettings,
    initialize_production_stores,
)
from packages.storage.sqlite import SQLiteRepository

DEFAULT_ANALYTICS_DB = Path(os.environ.get("ETR_ANALYTICS_DB", "state/research.db"))
DEFAULT_OBJECT_ROOT = Path(os.environ.get("ETR_OBJECT_ROOT", "state/objects"))
DEFAULT_REPORT_ROOT = Path(os.environ.get("ETR_REPORT_ROOT", "reports/generated"))
DEFAULT_MISSION_FEEDBACK_ROOT = Path(
    os.environ.get("ETR_MISSION_FEEDBACK_ROOT", "reports/mission-feedback")
)
DEFAULT_EMBEDDINGS_CONFIG = Path(
    configured_path("ETR_EMBEDDINGS_CONFIG", "config/embeddings.yaml")
)
DEFAULT_DISCOVERY_CONFIG = configured_path("ETR_DISCOVERY_CONFIG", "config/discovery.yaml")
DEFAULT_SCORING_CONFIG = configured_path("ETR_SCORING_CONFIG", "config/scoring.yaml")
DEFAULT_MODELS_CONFIG = configured_path("ETR_MODELS_CONFIG", "config/models.yaml")
DEFAULT_SOURCES_CONFIG = configured_path("ETR_SOURCES_CONFIG", "config/sources.yaml")
DEFAULT_SOURCE_TERMS_CONFIG = configured_path(
    "ETR_SOURCE_TERMS_CONFIG", "config/source-terms.yaml"
)
DEFAULT_IMPROVEMENT_CONFIG = configured_path("ETR_IMPROVEMENT_CONFIG", "config/improvement.yaml")
DEFAULT_MIGRATIONS_ROOT = configured_path("ETR_MIGRATIONS_ROOT", "migrations")

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
mission_app = typer.Typer(no_args_is_help=True)
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
app.add_typer(mission_app, name="mission")


@app.callback()
def configure_cli(
    env_file: Annotated[Path | None, typer.Option("--env-file")] = None,
) -> None:
    """Operate Emerging Telemetry Research with an optional non-executable environment file."""
    if env_file is not None:
        try:
            load_environment_file(env_file)
        except ValueError as exc:
            raise typer.BadParameter(str(exc)) from exc


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


def _json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
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
        os.environ.get("ETR_EMAIL_RECIPIENT") or None
    ),
    agent_mode: Annotated[str, typer.Option("--agent-mode")] = os.environ.get(
        "ETR_AGENT_MODE", "plan"
    ),
    agent_adapter: Annotated[str, typer.Option("--agent-adapter")] = os.environ.get(
        "ETR_AGENT_ADAPTER", "openclaw"
    ),
    agent_concurrency: Annotated[int, typer.Option("--agent-concurrency", min=1, max=8)] = 3,
    discovery_config: Annotated[Path, typer.Option("--discovery-config")] = (
        DEFAULT_DISCOVERY_CONFIG
    ),
    scoring_config: Annotated[Path, typer.Option("--scoring-config")] = DEFAULT_SCORING_CONFIG,
    models_config: Annotated[Path, typer.Option("--models-config")] = DEFAULT_MODELS_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if edition not in {"morning", "afternoon_delta", "weekly", "flash"}:
        raise typer.BadParameter("unsupported live edition")
    _require_deployment_capability(
        "collection",
        discovery_config=discovery_config,
    )
    stores = initialize_production_stores(
        ProductionStoreSettings(
            database_url=_required_env("ETR_DATABASE_URL"),
            s3_endpoint_url=_required_env("ETR_S3_ENDPOINT_URL"),
            s3_access_key_id=_required_env("ETR_S3_ACCESS_KEY_ID"),
            s3_secret_access_key=_required_env("ETR_S3_SECRET_ACCESS_KEY"),
            s3_bucket=_required_env("ETR_S3_BUCKET"),
            s3_region=os.environ.get("ETR_S3_REGION", "us-east-1"),
            server_side_encryption=_s3_encryption_mode(),
        ),
        migrations_root=DEFAULT_MIGRATIONS_ROOT,
    )
    provider = _agent_runtime(agent_mode, agent_adapter)
    daily_model_spend = Decimal(
        str(AnalyticsStore(analytics_db).cost_breakdown(days=1)["estimated_cost"])
    )
    result = asyncio.run(
        run_live_research(
            LiveRunSettings(
                output_root=output,
                discord_channel_id=None,
                email_recipient=email_recipient,
                edition=edition,
                agent_mode=agent_mode,
                agent_max_concurrency=agent_concurrency,
                discovery_config=discovery_config,
                scoring_config=scoring_config,
                models_config=models_config,
                daily_model_spend=daily_model_spend,
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
        "ETR_AGENT_MODE", "plan"
    ),
    agent_adapter: Annotated[str, typer.Option("--agent-adapter")] = os.environ.get(
        "ETR_AGENT_ADAPTER", "codex"
    ),
    agent_concurrency: Annotated[int, typer.Option("--agent-concurrency", min=1, max=8)] = 3,
    discovery_config: Annotated[Path, typer.Option("--discovery-config")] = (
        DEFAULT_DISCOVERY_CONFIG
    ),
    scoring_config: Annotated[Path, typer.Option("--scoring-config")] = DEFAULT_SCORING_CONFIG,
    models_config: Annotated[Path, typer.Option("--models-config")] = DEFAULT_MODELS_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run live discovery with SQLite, local immutable objects, and no external delivery."""
    if edition not in {"morning", "afternoon_delta", "weekly", "flash"}:
        raise typer.BadParameter("unsupported live edition")
    _require_deployment_capability(
        "collection",
        discovery_config=discovery_config,
    )
    provider = _agent_runtime(agent_mode, agent_adapter)
    daily_model_spend = Decimal(
        str(AnalyticsStore(database).cost_breakdown(days=1)["estimated_cost"])
    )
    result = asyncio.run(
        run_live_research(
            LiveRunSettings(
                output_root=output,
                discord_channel_id=None,
                edition=edition,
                agent_mode=agent_mode,
                agent_max_concurrency=agent_concurrency,
                discovery_config=discovery_config,
                scoring_config=scoring_config,
                models_config=models_config,
                daily_model_spend=daily_model_spend,
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
                "copy research.env.example to research.env",
                "configure BRAVE_API_KEY and XAI_API_KEY in a secret store",
                "run ./run-research.sh",
            ],
        },
        pretty=not json_output,
    )


@setup_app.command("init")
def setup_init(
    output: Annotated[Path, typer.Option("--output")] = Path("."),
    profile: Annotated[str, typer.Option("--profile")] = "portable",
    force: Annotated[bool, typer.Option("--force")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Create private, cross-platform local configuration and state directories."""
    try:
        result = initialize_workspace(output, profile=profile, force=force)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    result["next"] = [
        "emerging-telemetry-research setup secret-set BRAVE_API_KEY",
        "emerging-telemetry-research setup secret-set XAI_API_KEY",
        "emerging-telemetry-research setup approval-request",
        "review and apply the deployment approval request",
        "emerging-telemetry-research setup doctor --profile portable",
        "emerging-telemetry-research portable run --json",
    ]
    emit(result, pretty=not json_output)


@setup_app.command("secret-set")
def setup_secret_set(
    name: Annotated[str, typer.Argument()],
    config: Annotated[Path, typer.Option("--config")] = Path(
        ".emerging-telemetry-research/config.env"
    ),
    service: Annotated[str, typer.Option("--service")] = "emerging-telemetry-research",
    stdin: Annotated[bool, typer.Option("--stdin")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Store a secret in the OS credential store and write only its reference locally."""
    value = sys.stdin.read().rstrip("\r\n") if stdin else typer.prompt(
        f"Value for {name}", hide_input=True, confirmation_prompt=True
    )
    try:
        configure_keyring_credential(
            name,
            value,
            config_path=config,
            service=service,
        )
    except (SecretResolutionError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "name": name,
            "reference": keyring_reference(name, service=service),
            "value_exposed": False,
        },
        pretty=not json_output,
    )


@setup_app.command("doctor")
def setup_doctor(
    profile: Annotated[str, typer.Option("--profile")] = "core",
    config: Annotated[Path | None, typer.Option("--config")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Check platform, package, provider, secret, and profile readiness without leaking values."""
    try:
        result = run_doctor(profile=profile, config_path=config)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(result, pretty=not json_output)
    if not result["ready"]:
        raise typer.Exit(code=2)


@setup_app.command("approval-request")
def setup_approval_request(
    environment_id: Annotated[str, typer.Option("--environment-id")] = "local",
    output: Annotated[Path, typer.Option("--output")] = Path(
        ".emerging-telemetry-research/deployment-approval-request.json"
    ),
    allow_external_delivery: Annotated[
        bool, typer.Option("--allow-external-delivery")
    ] = False,
    allow_self_improvement_apply: Annotated[
        bool, typer.Option("--allow-self-improvement-apply")
    ] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Create a reviewable request bound to current code, policies, terms, and sources."""
    try:
        request = create_approval_request(
            environment_id=environment_id,
            allow_external_delivery=allow_external_delivery,
            allow_self_improvement_apply=allow_self_improvement_apply,
        )
        written = write_private_json(output, request)
    except DeploymentApprovalError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            **request,
            "request_path": str(written.resolve()),
            "next": (
                "review, then run `emerging-telemetry-research "
                "setup approval-apply REQUEST ...`"
            ),
        },
        pretty=not json_output,
    )


@setup_app.command("approval-apply")
def setup_approval_apply(
    request_path: Annotated[
        Path,
        typer.Argument(exists=True, dir_okay=False, readable=True),
    ],
    approved_by: Annotated[str, typer.Option("--approved-by")],
    approval_id: Annotated[str, typer.Option("--approval-id")],
    expires_days: Annotated[int, typer.Option("--expires-days", min=1, max=365)] = 30,
    output: Annotated[Path, typer.Option("--output")] = Path(
        ".emerging-telemetry-research/deployment-approval.yaml"
    ),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Apply an explicit operator approval to an unchanged deployment request."""
    try:
        approval = apply_approval_request(
            _json_object(request_path),
            approved_by=approved_by,
            approval_id=approval_id,
            expires_days=expires_days,
        )
        written = write_private_yaml(output, approval)
    except (DeploymentApprovalError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "status": "approved",
            "approval_path": str(written.resolve()),
            "expires_at": approval["expires_at"],
            "capabilities": approval["capabilities"],
            "source_ids": approval["source_ids"],
        },
        pretty=not json_output,
    )


@mission_app.command("create")
def mission_create(
    objective: Annotated[str | None, typer.Option("--objective", "-o")] = None,
    name: Annotated[str | None, typer.Option("--name")] = None,
    outcome: Annotated[
        str | None,
        typer.Option(
            "--result-type",
            "--outcome",
            help="Singular noun for a finding, such as opportunity, risk, or trend.",
        ),
    ] = None,
    window_hours: Annotated[int, typer.Option("--window-hours", min=1, max=2160)] = 168,
    cadence: Annotated[str, typer.Option("--cadence")] = "daily",
    output: Annotated[Path | None, typer.Option("--output")] = None,
    force: Annotated[bool, typer.Option("--force")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Describe a research objective and create a safe, reviewable mission draft."""
    stated_objective = objective or typer.prompt("What should this research mission investigate?")
    try:
        mission = draft_mission(
            stated_objective,
            name=name,
            outcome_noun=outcome,
            window_hours=window_hours,
            cadence=cadence,
        )
        destination = output or (
            Path("missions") / mission.mission_id.removeprefix("ms_") / "mission.yaml"
        )
        written = write_mission(mission, destination, force=force)
        compiled = compile_mission(mission)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "mission_id": mission.mission_id,
            "name": mission.name,
            "status": "draft",
            "mission_path": str(written),
            "query_count": len(compiled.queries),
            "collection_authorized": False,
            "next": [
                f"research mission plan {written}",
                f"research mission activate {written} --approved-by NAME --approval-id ID",
            ],
        },
        pretty=not json_output,
    )


@mission_app.command("validate")
def mission_validate(
    mission_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Validate the mission contract and its proven five-role workflow."""
    try:
        mission = load_mission(mission_path)
        compiled = compile_mission(mission)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "mission_id": mission.mission_id,
            "valid": True,
            "mission_sha256": compiled.mission_sha256,
            "query_count": len(compiled.queries),
            "collection_authorized": compiled.collection_authorized,
        },
        pretty=not json_output,
    )


@mission_app.command("plan")
def mission_plan(
    mission_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Show exactly what the mission will query and which roles will review it."""
    try:
        compiled = compile_mission(load_mission(mission_path))
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(compiled.to_contract(), pretty=not json_output)


@mission_app.command("activate")
def mission_activate(
    mission_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    approved_by: Annotated[str, typer.Option("--approved-by")],
    approval_id: Annotated[str, typer.Option("--approval-id")],
    output: Annotated[Path | None, typer.Option("--output")] = None,
    receipt: Annotated[Path | None, typer.Option("--receipt")] = None,
    force: Annotated[bool, typer.Option("--force")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Approve a bounded source plan and write a reversible active mission."""
    destination = output or mission_path.with_name("mission.active.yaml")
    receipt_path = receipt or mission_path.with_name("activation-receipt.json")
    try:
        activation = activate_mission(
            load_mission(mission_path),
            approved_by=approved_by,
            approval_id=approval_id,
        )
        mission_written = write_mission(activation.mission, destination, force=force)
        receipt_written = write_activation_receipt(
            activation.receipt,
            receipt_path,
            force=force,
        )
        compiled = compile_mission(activation.mission)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "mission_id": activation.mission.mission_id,
            "status": "active",
            "collection_authorized": compiled.collection_authorized,
            "mission_path": str(mission_written),
            "receipt_path": str(receipt_written),
            "rollback": f"research mission rollback {receipt_written}",
        },
        pretty=not json_output,
    )


@mission_app.command("rollback")
def mission_rollback(
    receipt: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    output: Annotated[Path, typer.Option("--output")] = Path("mission.rolled-back.yaml"),
    force: Annotated[bool, typer.Option("--force")] = False,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Restore the exact plan-mode mission recorded before activation."""
    try:
        value = _json_object(receipt)
        mission = rollback_mission(value)
        written = write_mission(mission, output, force=force)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "mission_id": mission.mission_id,
            "status": "plan",
            "collection_authorized": False,
            "mission_path": str(written),
        },
        pretty=not json_output,
    )


@mission_app.command("run")
def mission_run_command(
    mission_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    signals: Annotated[
        Path | None,
        typer.Option("--signals", exists=True, dir_okay=False, readable=True),
    ] = None,
    live: Annotated[bool, typer.Option("--live")] = False,
    output: Annotated[Path, typer.Option("--output")] = Path("reports/missions"),
    agent_mode: Annotated[str, typer.Option("--agent-mode")] = "plan",
    agent_adapter: Annotated[str, typer.Option("--agent-adapter")] = "codex",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run an approved live mission or a safe fixture mission."""
    if live == (signals is not None):
        raise typer.BadParameter("choose exactly one of --live or --signals")
    try:
        mission = load_mission(mission_path)
        if live:
            _require_deployment_capability("collection")
            compiled = compile_mission(mission)
            signal_payload = asyncio.run(
                collect_mission_signals(
                    compiled,
                    BraveSearchClient(_required_env("BRAVE_API_KEY")),
                )
            )
        else:
            if signals is None:
                raise ValueError("signals path is required")
            signal_payload = _json_object(signals)
        provider = _agent_runtime(agent_mode, agent_adapter)
        result = asyncio.run(
            run_mission(
                mission,
                signal_payload,
                output,
                agent_mode=agent_mode,
                agent_provider=provider,
            )
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            "mission_id": mission.mission_id,
            "run_id": result.report["run_id"],
            "report_id": result.report["report_id"],
            "outcome_count": len(result.report["outcomes"]),
            "report_json": str(result.report_json_path),
            "report_html": str(result.report_html_path),
            "run_manifest": str(result.run_manifest_path),
            "external_delivery": "disabled",
        },
        pretty=not json_output,
    )


@mission_app.command("evaluate")
def mission_evaluate(
    mission_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    report: Annotated[
        Path,
        typer.Option("--report", exists=True, dir_okay=False, readable=True),
    ],
    feedback_root: Annotated[Path, typer.Option("--feedback-root")] = (
        DEFAULT_MISSION_FEEDBACK_ROOT
    ),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Check report quality against the mission's declared success gates."""
    try:
        mission = load_mission(mission_path)
        feedback = load_mission_feedback(feedback_root, mission.mission_id)
        result = evaluate_mission_report(
            mission,
            _json_object(report),
            feedback=feedback,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(result, pretty=not json_output)
    if not result["passed"]:
        raise typer.Exit(code=2)


@mission_app.command("feedback")
def mission_feedback(
    mission_path: Annotated[Path, typer.Argument(exists=True, dir_okay=False, readable=True)],
    report: Annotated[
        Path,
        typer.Option("--report", exists=True, dir_okay=False, readable=True),
    ],
    outcome_id: Annotated[str, typer.Option("--outcome-id")],
    label: Annotated[str, typer.Option("--label")],
    reason: Annotated[str, typer.Option("--reason")],
    submitted_by: Annotated[str, typer.Option("--submitted-by")],
    output: Annotated[Path, typer.Option("--output")] = DEFAULT_MISSION_FEEDBACK_ROOT,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Record an immutable outcome usefulness decision for mission calibration."""
    try:
        payload, path = record_mission_feedback(
            load_mission(mission_path),
            _json_object(report),
            outcome_id=outcome_id,
            label=label,
            reason=reason,
            submitted_by=submitted_by,
            output_root=output,
        )
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    emit(
        {
            **payload,
            "feedback_path": str(path),
            "next": (
                f"research mission evaluate {mission_path} --report {report} "
                f"--feedback-root {output}"
            ),
        },
        pretty=not json_output,
    )


@mission_app.command("list")
def mission_list(
    root: Annotated[Path, typer.Option("--root", exists=True, file_okay=False)] = (
        BUILTIN_MISSIONS_ROOT
    ),
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """List mission packs and their activation state."""
    missions: list[dict[str, Any]] = []
    for path in sorted(root.glob("**/mission*.yaml")):
        try:
            mission = load_mission(path)
            compiled = compile_mission(mission)
        except ValueError:
            continue
        missions.append(
            {
                "mission_id": mission.mission_id,
                "name": mission.name,
                "mode": mission.payload["governance"]["collection_mode"],
                "collection_authorized": compiled.collection_authorized,
                "path": str(path),
            }
        )
    emit({"missions": missions}, pretty=not json_output)


def _s3_encryption_mode() -> str | None:
    value = os.environ.get("ETR_S3_SERVER_SIDE_ENCRYPTION", "AES256")
    if value == "AES256":
        return value
    if value == "none":
        return None
    raise typer.BadParameter("ETR_S3_SERVER_SIDE_ENCRYPTION must be AES256 or none")


def _agent_runtime(mode: str, adapter: str) -> AgentProvider | None:
    if mode not in AGENT_MODES:
        raise typer.BadParameter("agent mode must be one of: " + ", ".join(AGENT_MODES))
    if mode == "plan":
        return None
    try:
        return build_agent_provider(adapter)
    except ValueError as exc:
        builtins = ", ".join(AGENT_ADAPTERS)
        raise typer.BadParameter(f"{exc}; built-in adapters: {builtins}") from exc


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
        os.environ.get("ETR_EMAIL_RECIPIENT") or None
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
    if os.environ.get("ETR_EMAIL_DELIVERY_ENABLED", "").lower() != "true":
        raise typer.BadParameter("email delivery is disabled")
    _require_deployment_capability("external_delivery")
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
        "direct CLI delivery is forbidden; use the reviewed research_delivery_send OpenClaw tool"
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
        "ETR_AGENT_ADAPTER", "fixture"
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
    ] = DEFAULT_SCORING_CONFIG,
    improvement_config: Annotated[
        Path,
        typer.Option(
            "--improvement-config",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = DEFAULT_IMPROVEMENT_CONFIG,
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


@improve_app.command("advise")
def improve_advise(
    reports: Annotated[Path, typer.Option("--reports")] = Path("reports/generated"),
    feedback: Annotated[Path, typer.Option("--feedback")] = Path("reports/feedback"),
    mission_feedback: Annotated[Path, typer.Option("--mission-feedback")] = Path(
        "reports/mission-feedback"
    ),
    output: Annotated[Path, typer.Option("--output")] = Path(
        "reports/generated/improvement-advice"
    ),
    improvement_config: Annotated[
        Path,
        typer.Option(
            "--improvement-config",
            exists=True,
            dir_okay=False,
            readable=True,
        ),
    ] = DEFAULT_IMPROVEMENT_CONFIG,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Measure all improvement domains and emit proposal-only recommendations."""
    result = run_advisory_cycle(
        reports_root=reports,
        feedback_root=feedback,
        mission_feedback_root=mission_feedback,
        output_root=output,
        improvement_config=improvement_config,
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
    _require_deployment_capability("self_improvement_apply")
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
    _require_deployment_capability("self_improvement_apply")
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
    try:
        value = resolve_secret(name)
    except SecretResolutionError as exc:
        raise typer.BadParameter(str(exc)) from exc
    if value is None:
        raise typer.BadParameter(f"{name} is required")
    return value


def _require_deployment_capability(
    capability: str,
    *,
    discovery_config: Path = DEFAULT_DISCOVERY_CONFIG,
) -> None:
    try:
        require_deployment_approval(
            capability,
            paths=DeploymentControlPaths(
                discovery=discovery_config,
                sources=DEFAULT_SOURCES_CONFIG,
                source_terms=DEFAULT_SOURCE_TERMS_CONFIG,
            ),
        )
    except DeploymentApprovalError as exc:
        raise typer.BadParameter(str(exc)) from exc


def _optional_reddit_client() -> RedditSearchClient | None:
    access_token = resolve_secret("REDDIT_ACCESS_TOKEN", required=False)
    user_agent = os.environ.get("REDDIT_USER_AGENT")
    if not access_token or not user_agent:
        return None
    return RedditSearchClient(access_token, user_agent=user_agent)


def _optional_tiktok_client() -> TikTokResearchClient | None:
    access_token = resolve_secret("TIKTOK_RESEARCH_ACCESS_TOKEN", required=False)
    if not access_token:
        return None
    return TikTokResearchClient(access_token)


if __name__ == "__main__":
    app()
