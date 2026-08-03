from __future__ import annotations

import os
import re
from collections.abc import MutableMapping
from pathlib import Path

ENVIRONMENT_NAME = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
MAX_ENVIRONMENT_BYTES = 65_536
MAX_ENVIRONMENT_VALUES = 512


def parse_environment_file(path: Path) -> dict[str, str]:
    if not path.is_file() or path.stat().st_size > MAX_ENVIRONMENT_BYTES:
        raise ValueError("environment file is missing or too large")
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"environment file line {line_number} must be NAME=VALUE")
        name, raw_value = line.split("=", 1)
        name = name.strip()
        if not ENVIRONMENT_NAME.fullmatch(name):
            raise ValueError(f"environment file line {line_number} has an invalid name")
        if name in values:
            raise ValueError(f"environment file repeats {name}")
        value = raw_value.strip()
        if value.startswith(("'", '"')):
            quote = value[0]
            if len(value) < 2 or value[-1] != quote:
                raise ValueError(f"environment file line {line_number} has unmatched quotes")
            value = value[1:-1]
        if "\x00" in value:
            raise ValueError(f"environment file line {line_number} contains a NUL byte")
        values[name] = value
        if len(values) > MAX_ENVIRONMENT_VALUES:
            raise ValueError("environment file contains too many values")
    return values


def load_environment_file(
    path: Path,
    *,
    environ: MutableMapping[str, str] | None = None,
    override: bool = False,
) -> tuple[str, ...]:
    target = environ if environ is not None else os.environ
    loaded: list[str] = []
    for name, value in parse_environment_file(path).items():
        if name not in target or override:
            target[name] = value
            loaded.append(name)
    return tuple(loaded)
