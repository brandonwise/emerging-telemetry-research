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

from packages.common.canonical import canonical_json_bytes
from packages.connectors.live import OfficialSourceClient
from packages.delivery.discord import build_discord_delivery_plan
from packages.discovery.clients import BraveSearchClient, XaiXSearchClient
from packages.evaluation.harness import run_acceptance_suite
from packages.improvement.controller import (
    ALL_TAXONOMIES,
    apply_proposal,
    record_feedback,
    rollback_proposal,
    run_improvement_cycle,
)
from packages.pipeline.frozen import run_frozen_fixture
from packages.pipeline.live import LiveRunSettings, run_live_radar
from packages.storage.runtime import (
    ProductionStoreSettings,
    initialize_production_stores,
)

app = typer.Typer(no_args_is_help=True)
run_app = typer.Typer(no_args_is_help=True)
fixture_app = typer.Typer(no_args_is_help=True)
report_app = typer.Typer(no_args_is_help=True)
eval_app = typer.Typer(no_args_is_help=True)
live_app = typer.Typer(no_args_is_help=True)
feedback_app = typer.Typer(no_args_is_help=True)
improve_app = typer.Typer(no_args_is_help=True)
app.add_typer(run_app, name="run")
app.add_typer(fixture_app, name="fixture")
app.add_typer(report_app, name="report")
app.add_typer(eval_app, name="eval")
app.add_typer(live_app, name="live")
app.add_typer(feedback_app, name="feedback")
app.add_typer(improve_app, name="improve")


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
    channel_id: Annotated[str, typer.Option("--channel-id")] = "1476897068885872814",
    edition: Annotated[str, typer.Option("--edition")] = "morning",
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if not channel_id.isdigit():
        raise typer.BadParameter("Discord channel ID must be numeric")
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
    result = asyncio.run(
        run_live_radar(
            LiveRunSettings(
                output_root=output,
                discord_channel_id=channel_id,
                edition=edition,
            ),
            brave_client=BraveSearchClient(_required_env("BRAVE_API_KEY")),
            x_search_client=XaiXSearchClient(_required_env("XAI_API_KEY")),
            official_client=OfficialSourceClient(),
            object_store=stores.object_store,
            repository=stores.repository,
        )
    )
    emit(
        {
            "run_id": result.run_id,
            "report_id": result.report["report_id"],
            "report_json": str(result.report_json_path.resolve()),
            "html_path": str(result.rendered.path.resolve()),
            "delivery_plan": str(result.delivery_plan_path.resolve()),
            "idempotency_key": result.delivery_plan["idempotency_key"],
            "summary": result.summary,
            "candidate_cves": list(result.candidate_cves),
            "degraded_sources": list(result.degraded_sources),
            "external_delivery": "ready",
        },
        pretty=not json_output,
    )


def _s3_encryption_mode() -> str | None:
    value = os.environ.get("RADAR_S3_SERVER_SIDE_ENCRYPTION", "AES256")
    if value == "AES256":
        return value
    if value == "none":
        return None
    raise typer.BadParameter(
        "RADAR_S3_SERVER_SIDE_ENCRYPTION must be AES256 or none"
    )


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
    notes: Annotated[str | None, typer.Option("--notes")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    if taxonomy not in ALL_TAXONOMIES:
        raise typer.BadParameter(
            "taxonomy must be one of: " + ", ".join(sorted(ALL_TAXONOMIES))
        )
    feedback, path = record_feedback(
        report_path=report_json,
        finding_id=finding_id,
        taxonomy=taxonomy,
        submitted_by=submitted_by,
        output_root=output,
        notes=notes,
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
    output: Annotated[Path, typer.Option("--output")] = Path(
        "reports/generated/improvement"
    ),
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


if __name__ == "__main__":
    app()
