from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from importlib import metadata
from pathlib import Path
from typing import Any

from packages.agents.runtime import AGENT_PROVIDER_ENTRY_POINT_GROUP
from packages.common.canonical import canonical_json_bytes, format_timestamp, sha256_hex
from packages.security_gateway.deployment import write_private_json
from packages.security_gateway.secrets import inspect_secret

COMMAND_HARNESSES = ("openclaw", "codex", "claude")


@dataclass(frozen=True, slots=True)
class HarnessStatus:
    harness: str
    available: bool
    version: str | None
    authentication: str
    detail: str
    contract_test_required: bool

    def to_contract(self) -> dict[str, object]:
        return asdict(self)


def inspect_harnesses() -> tuple[HarnessStatus, ...]:
    statuses = [_inspect_command_harness(name) for name in COMMAND_HARNESSES]
    api_key = inspect_secret("ETR_AGENT_API_KEY")
    model = os.environ.get("ETR_AGENT_MODEL", "").strip()
    base_url = os.environ.get("ETR_AGENT_BASE_URL", "").strip()
    http_ready = api_key.configured and bool(model) and base_url.startswith("https://")
    statuses.append(
        HarnessStatus(
            harness="openai-compatible",
            available=http_ready,
            version=None,
            authentication="configured" if api_key.configured else "not_configured",
            detail=(
                "HTTPS endpoint, model, and secret reference configured"
                if http_ready
                else "configure an HTTPS endpoint, model, and ETR_AGENT_API_KEY reference"
            ),
            contract_test_required=http_ready,
        )
    )
    installed_plugins = sorted(
        entry.name for entry in metadata.entry_points(group=AGENT_PROVIDER_ENTRY_POINT_GROUP)
    )
    for plugin in installed_plugins:
        statuses.append(
            HarnessStatus(
                harness=plugin,
                available=True,
                version=_distribution_version(plugin),
                authentication="plugin_managed",
                detail="installed provider plugin; explicit allowlist and contract test required",
                contract_test_required=True,
            )
        )
    return tuple(statuses)


def harness_status(name: str) -> HarnessStatus | None:
    return next((item for item in inspect_harnesses() if item.harness == name), None)


def write_harness_test_receipt(
    path: Path,
    *,
    status: HarnessStatus,
    evaluation: dict[str, Any],
    tested_at: datetime | None = None,
) -> Path:
    if evaluation.get("passed") is not True:
        raise ValueError("harness evaluation did not pass")
    timestamp = (tested_at or datetime.now(UTC)).astimezone(UTC)
    receipt = {
        "schema_version": "1.0",
        "harness": status.harness,
        "harness_fingerprint": harness_fingerprint(status),
        "tested_at": format_timestamp(timestamp),
        "expires_at": format_timestamp(timestamp + timedelta(days=30)),
        "evaluation_sha256": sha256_hex(canonical_json_bytes(evaluation)),
        "gates": evaluation.get("gates", {}),
        "passed": True,
    }
    return write_private_json(path, receipt)


def valid_harness_test_receipt(
    path: Path,
    *,
    status: HarnessStatus,
    now: datetime | None = None,
) -> bool:
    try:
        value = _json_object(path)
        expires_at = datetime.fromisoformat(str(value["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, OSError, ValueError):
        return False
    current = (now or datetime.now(UTC)).astimezone(UTC)
    return bool(
        value.get("schema_version") == "1.0"
        and value.get("passed") is True
        and value.get("harness") == status.harness
        and value.get("harness_fingerprint") == harness_fingerprint(status)
        and expires_at.tzinfo is not None
        and current < expires_at.astimezone(UTC)
    )


def harness_fingerprint(status: HarnessStatus) -> str:
    return sha256_hex(
        canonical_json_bytes(
            {
                "harness": status.harness,
                "version": status.version,
                "model": os.environ.get("ETR_AGENT_MODEL", "").strip() or None,
                "base_url": os.environ.get("ETR_AGENT_BASE_URL", "").strip() or None,
                "executable": os.environ.get("ETR_AGENT_EXECUTABLE", "").strip() or None,
            }
        )
    )


def _inspect_command_harness(name: str) -> HarnessStatus:
    executable = shutil.which(os.environ.get("ETR_AGENT_EXECUTABLE", name))
    if executable is None:
        return HarnessStatus(
            harness=name,
            available=False,
            version=None,
            authentication="unknown",
            detail=f"{name} command not found",
            contract_test_required=False,
        )
    version = _command_version(executable)
    return HarnessStatus(
        harness=name,
        available=True,
        version=version,
        authentication="unverified",
        detail="command available; run setup harness-test before shadow or active mode",
        contract_test_required=True,
    )


def _command_version(executable: str) -> str | None:
    allowed_environment = {
        key: value
        for key, value in os.environ.items()
        if key in {"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"}
    }
    try:
        completed = subprocess.run(  # noqa: S603 - resolved executable and fixed version flag.
            (executable, "--version"),
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            env=allowed_environment,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return output[0][:200] if completed.returncode == 0 and output else None


def _distribution_version(plugin: str) -> str | None:
    try:
        return metadata.version(plugin)
    except metadata.PackageNotFoundError:
        return None


def _json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("harness receipt must contain one object")
    return value
