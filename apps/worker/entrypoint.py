from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from pathlib import Path

from packages.onboarding.environment import load_environment_file


def _environment_files(arguments: Sequence[str]) -> tuple[Path, ...]:
    explicit: list[Path] = []
    for index, argument in enumerate(arguments):
        if argument == "--env-file":
            if index + 1 >= len(arguments):
                raise SystemExit("--env-file requires a path")
            explicit.append(Path(arguments[index + 1]))
        if argument.startswith("--env-file="):
            explicit.append(Path(argument.split("=", 1)[1]))
    files: list[Path] = []
    default = Path(".emerging-telemetry-research/config.env")
    if default.is_file():
        files.append(default)
    configured = os.environ.get("ETR_ENV_FILE")
    if configured:
        files.append(Path(configured))
    files.extend(explicit)
    unique: list[Path] = []
    for path in files:
        if path not in unique:
            unique.append(path)
    return tuple(unique)


def main() -> None:
    for index, environment_file in enumerate(_environment_files(sys.argv[1:])):
        load_environment_file(environment_file, override=index > 0)
    from apps.worker.cli import app

    app()


if __name__ == "__main__":
    main()
