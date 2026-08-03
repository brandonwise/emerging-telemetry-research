from __future__ import annotations

import os
from pathlib import Path

BUNDLED_ROOT = Path(__file__).resolve().parents[2]


def bundled_path(relative: str | Path) -> Path:
    path = Path(relative)
    if path.is_absolute():
        return path
    local = Path.cwd() / path
    return local if local.exists() else BUNDLED_ROOT / path


def configured_path(environment_name: str, relative: str | Path) -> Path:
    configured = os.environ.get(environment_name, "").strip()
    return Path(configured) if configured else bundled_path(relative)
