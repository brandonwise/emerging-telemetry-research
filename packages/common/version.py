from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

try:
    PROJECT_VERSION = version("emerging-telemetry-research")
except PackageNotFoundError:  # pragma: no cover - source trees are normally installed by uv.
    PROJECT_VERSION = "0+unknown"
