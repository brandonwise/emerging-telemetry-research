from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any
from uuid import uuid4

import typer

from packages.common.canonical import canonical_json_bytes
from packages.delivery.discord import build_discord_delivery_plan
from packages.evaluation.harness import run_acceptance_suite
from packages.pipeline.frozen import run_frozen_fixture

app = typer.Typer(no_args_is_help=True)
run_app = typer.Typer(no_args_is_help=True)
fixture_app = typer.Typer(no_args_is_help=True)
report_app = typer.Typer(no_args_is_help=True)
eval_app = typer.Typer(no_args_is_help=True)
app.add_typer(run_app, name="run")
app.add_typer(fixture_app, name="fixture")
app.add_typer(report_app, name="report")
app.add_typer(eval_app, name="eval")


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


if __name__ == "__main__":
    app()
