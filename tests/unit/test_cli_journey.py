from __future__ import annotations

import json
import shlex
from pathlib import Path

from typer.testing import CliRunner

from apps.worker.cli import CLI_COMMAND, app


def _payload(output: str) -> dict[str, object]:
    value = json.loads(output)
    assert isinstance(value, dict)
    return value


def _cli_arguments(command: str) -> list[str]:
    prefix = f"{CLI_COMMAND} "
    assert command.startswith(prefix)
    return shlex.split(command.removeprefix(prefix))


def test_setup_init_prints_source_checkout_commands(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["setup", "init", "--output", str(tmp_path), "--profile", "core", "--json"],
    )

    assert result.exit_code == 0, result.output
    payload = _payload(result.output)
    next_steps = payload["next"]
    assert isinstance(next_steps, list)
    commands = [
        item
        for item in next_steps
        if isinstance(item, str)
        and item != "review and apply the deployment approval request"
    ]
    assert commands
    assert all(command.startswith(CLI_COMMAND) for command in commands)
    assert "setup doctor --profile core" in commands[-2]


def test_mission_create_prints_an_executable_plan_command(tmp_path: Path) -> None:
    runner = CliRunner()
    mission_path = tmp_path / "mission.yaml"
    created = runner.invoke(
        app,
        [
            "mission",
            "create",
            "--objective",
            "Find recurring developer workflow pain that is actionable this quarter.",
            "--result-type",
            "opportunity",
            "--output",
            str(mission_path),
            "--json",
        ],
    )

    assert created.exit_code == 0, created.output
    payload = _payload(created.output)
    next_steps = payload["next"]
    assert isinstance(next_steps, list)
    plan_command = str(next_steps[0])
    planned = runner.invoke(app, [*_cli_arguments(plan_command), "--json"])
    assert planned.exit_code == 0, planned.output
    assert _payload(planned.output)["collection_authorized"] is False
