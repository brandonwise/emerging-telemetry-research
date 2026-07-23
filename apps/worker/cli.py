"""Workflow CLI contract used by the Lobster files.

The commands intentionally return JSON so Lobster can pass typed results between
steps. Most handlers are placeholders that make the build sequence explicit.
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import typer

app = typer.Typer(no_args_is_help=True)
run_app = typer.Typer()
report_app = typer.Typer()
eval_app = typer.Typer()
app.add_typer(run_app, name="run")
app.add_typer(report_app, name="report")
app.add_typer(eval_app, name="eval")


def emit(payload: dict[str, Any]) -> None:
    typer.echo(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def read_stdin_json() -> dict[str, Any]:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def step_result(step: str, input_payload: dict[str, Any] | None = None) -> dict[str, Any]:
    base = input_payload or {}
    return {
        **base,
        "step": step,
        "step_completed_at": datetime.now(UTC).isoformat(),
        "implementation_status": "scaffold_only",
    }


@run_app.command("create")
def create_run(mode: str, edition: str = "none", json_output: bool = typer.Option(False, "--json")) -> None:
    del json_output
    emit({
        "run_id": f"run_{uuid4().hex}",
        "mode": mode,
        "edition": edition,
        "created_at": datetime.now(UTC).isoformat(),
    })


@run_app.command("finalize")
def finalize_run(json_output: bool = typer.Option(False, "--json")) -> None:
    del json_output
    emit(step_result("finalized", read_stdin_json()))


for command_name in ("collect", "quarantine", "sanitize", "extract", "correlate", "score", "analyze", "challenge", "verify"):
    def make_command(name: str):
        def command(
            run_from_stdin: bool = typer.Option(False, "--run-from-stdin"),
            json_output: bool = typer.Option(False, "--json"),
        ) -> None:
            del run_from_stdin, json_output
            emit(step_result(name, read_stdin_json()))
        command.__name__ = name
        return command
    app.command(command_name)(make_command(command_name))


@report_app.command("render")
def render_report(
    run_from_stdin: bool = typer.Option(False, "--run-from-stdin"),
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    del run_from_stdin, json_output
    payload = step_result("rendered", read_stdin_json())
    payload.update({"auto_publish": True, "requires_human_approval": False})
    emit(payload)


@report_app.command("approval-preview")
def approval_preview(json_output: bool = typer.Option(False, "--json")) -> None:
    del json_output
    emit(step_result("approval_preview", read_stdin_json()))


@report_app.command("deliver")
def deliver_report(json_output: bool = typer.Option(False, "--json")) -> None:
    del json_output
    emit(step_result("delivered", read_stdin_json()))


for command_name in ("prepare", "replay", "injection", "reliability", "score", "report"):
    def make_eval_command(name: str):
        def command(
            suite: str = "weekly-production-retrospective",
            json_output: bool = typer.Option(False, "--json"),
        ) -> None:
            del json_output
            payload = read_stdin_json()
            payload["suite"] = payload.get("suite", suite)
            emit(step_result(f"eval_{name}", payload))
        command.__name__ = f"eval_{name}"
        return command
    eval_app.command(command_name)(make_eval_command(command_name))


if __name__ == "__main__":
    app()
