from __future__ import annotations

import os
import sys
from collections.abc import Sequence
from pathlib import Path

from packages.onboarding.environment import load_environment_file


def _environment_file(arguments: Sequence[str]) -> Path | None:
    for index, argument in enumerate(arguments):
        if argument == "--env-file":
            if index + 1 >= len(arguments):
                raise SystemExit("--env-file requires a path")
            return Path(arguments[index + 1])
        if argument.startswith("--env-file="):
            return Path(argument.split("=", 1)[1])
    configured = os.environ.get("RADAR_ENV_FILE")
    if configured:
        return Path(configured)
    default = Path(".outcome-radar/config.env")
    return default if default.is_file() else None


def main() -> None:
    environment_file = _environment_file(sys.argv[1:])
    if environment_file is not None:
        load_environment_file(environment_file)
    from apps.worker.cli import app

    app()


if __name__ == "__main__":
    main()
