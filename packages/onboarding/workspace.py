from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit

import yaml

from packages.security_gateway.permissions import harden_private_path
from packages.security_gateway.secrets import inspect_secret, store_keyring_secret

RESOURCE_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIRECTORY = ".outcome-radar"
DEFAULT_CONFIG = """# Outcome Radar local configuration. This directory is ignored by Git.
# Store credentials with `outcome-radar setup secret-set NAME`; only keyring references appear here.
RADAR_AGENT_MODE=plan
RADAR_AGENT_ADAPTER=auto
RADAR_AGENT_API_KEY_REF=
RADAR_AGENT_INPUT_PRICE_PER_MILLION=
RADAR_AGENT_OUTPUT_PRICE_PER_MILLION=
RADAR_AGENT_PLUGIN_ALLOWLIST=
RADAR_COLLECTOR_PLUGIN_ALLOWLIST=
BRAVE_API_KEY_REF=
XAI_API_KEY_REF=
RADAR_DATABASE_URL_REF=
RADAR_S3_ENDPOINT_URL=http://127.0.0.1:19000
RADAR_S3_ACCESS_KEY_ID_REF=
RADAR_S3_SECRET_ACCESS_KEY_REF=
RADAR_S3_BUCKET=outcome-radar-evidence
RADAR_S3_REGION=us-east-1
RADAR_ANALYTICS_DB=state/radar.db
RADAR_OBJECT_ROOT=state/objects
RADAR_REPORT_ROOT=reports/generated
RADAR_DISCOVERY_CONFIG=.outcome-radar/config/discovery.yaml
RADAR_SOURCES_CONFIG=.outcome-radar/config/sources.yaml
RADAR_SOURCE_TERMS_CONFIG=.outcome-radar/config/source-terms.yaml
RADAR_SCORING_CONFIG=.outcome-radar/config/scoring.yaml
RADAR_MODELS_CONFIG=.outcome-radar/config/models.yaml
RADAR_EMBEDDINGS_CONFIG=.outcome-radar/config/embeddings.yaml
EXTERNAL_DELIVERY_ENABLED=false
RADAR_EMAIL_DELIVERY_ENABLED=false
"""
PRIVATE_IGNORE = "*\n!.gitignore\n"
SECRET_GROUPS = {
    "portable": ("BRAVE_API_KEY", "XAI_API_KEY"),
    "production": (
        "BRAVE_API_KEY",
        "XAI_API_KEY",
        "RADAR_DATABASE_URL",
        "RADAR_S3_ACCESS_KEY_ID",
        "RADAR_S3_SECRET_ACCESS_KEY",
    ),
}
PORTABLE_SOURCE_IDS = {
    "brave-web",
    "cisa-kev",
    "cve-list-v5",
    "first-epss",
    "github-advisories",
    "nvd-cve",
    "osv",
    "reddit-security-web",
    "tiktok-security",
    "x-researchers",
}


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    name: str
    status: Literal["pass", "warn", "fail"]
    detail: str
    required: bool


def initialize_workspace(
    output_root: Path,
    *,
    profile: str = "portable",
    force: bool = False,
) -> dict[str, object]:
    if profile not in {"core", "portable", "production"}:
        raise ValueError("setup profile must be core, portable, or production")
    root = output_root.resolve()
    config_root = root / CONFIG_DIRECTORY
    created: list[str] = []
    skipped: list[str] = []
    for directory in (config_root, root / "state/objects", root / "reports/generated"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        harden_private_path(directory)
    files = {
        config_root / "config.env": DEFAULT_CONFIG,
        config_root / ".gitignore": PRIVATE_IGNORE,
    }
    for path, content in files.items():
        if path.exists() and not force:
            skipped.append(str(path))
            continue
        path.write_text(content, encoding="utf-8")
        harden_private_path(path)
        created.append(str(path))
    local_config_root = config_root / "config"
    local_config_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    harden_private_path(local_config_root)
    for source in sorted((RESOURCE_ROOT / "config").glob("*.yaml")):
        destination = local_config_root / source.name
        if destination.exists() and not force:
            skipped.append(str(destination))
            continue
        if source.name == "sources.yaml" and profile in {"portable", "production"}:
            value = yaml.safe_load(source.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or not isinstance(value.get("sources"), list):
                raise ValueError("bundled source configuration is invalid")
            for item in value["sources"]:
                if isinstance(item, dict):
                    item["enabled"] = item.get("id") in PORTABLE_SOURCE_IDS
            destination.write_text(
                yaml.safe_dump(value, sort_keys=False),
                encoding="utf-8",
            )
        else:
            shutil.copyfile(source, destination)
        harden_private_path(destination)
        created.append(str(destination))
    return {
        "root": str(root),
        "profile": profile,
        "config": str(config_root / "config.env"),
        "created": created,
        "skipped": skipped,
        "external_delivery": "disabled",
    }


def configure_keyring_secret(
    name: str,
    value: str,
    *,
    config_path: Path,
    service: str = "outcome-radar",
) -> str:
    reference = store_keyring_secret(name, value, service=service)
    _set_config_value(config_path, f"{name}_REF", reference)
    return reference


def run_doctor(*, profile: str = "core", config_path: Path | None = None) -> dict[str, object]:
    if profile not in {"core", "portable", "production"}:
        raise ValueError("doctor profile must be core, portable, or production")
    checks: list[DoctorCheck] = []
    supported_python = (3, 12) <= sys.version_info[:2] < (3, 15)
    checks.append(
        DoctorCheck(
            "python",
            "pass" if supported_python else "fail",
            platform.python_version(),
            True,
        )
    )
    system = platform.system().lower()
    supported_system = system in {"darwin", "linux", "windows"}
    checks.append(
        DoctorCheck(
            "operating-system",
            "pass" if supported_system else "fail",
            f"{platform.system()} {platform.machine()}",
            True,
        )
    )
    resources = (
        "config/models.yaml",
        "schemas/mission.schema.json",
        "missions/developer-product-opportunities/mission.yaml",
        "integrations/templates/common/radar.env.example",
    )
    missing = [item for item in resources if not (RESOURCE_ROOT / item).is_file()]
    checks.append(
        DoctorCheck(
            "packaged-resources",
            "fail" if missing else "pass",
            "missing: " + ", ".join(missing) if missing else "runtime contracts available",
            True,
        )
    )
    selected_config = config_path or Path(CONFIG_DIRECTORY) / "config.env"
    if selected_config.is_file():
        permission_warning = (
            os.name != "nt" and bool(selected_config.stat().st_mode & 0o077)
        )
        checks.append(
            DoctorCheck(
                "local-config-permissions",
                "warn" if permission_warning else "pass",
                "group/world-readable" if permission_warning else "owner-only",
                False,
            )
        )
    else:
        checks.append(
            DoctorCheck(
                "local-config",
                "warn",
                "run `outcome-radar setup init` to create local defaults",
                False,
            )
        )
    required_secrets = SECRET_GROUPS.get(profile, ())
    for name in required_secrets:
        status = inspect_secret(name)
        checks.append(
            DoctorCheck(
                f"secret:{name}",
                "pass" if status.configured else "fail",
                status.source if status.configured else status.error or "not configured",
                True,
            )
        )
    if profile == "production":
        endpoint = os.environ.get("RADAR_S3_ENDPOINT_URL", "").strip()
        parsed_endpoint = urlsplit(endpoint)
        local_endpoint = parsed_endpoint.hostname in {"127.0.0.1", "::1", "localhost"}
        endpoint_valid = bool(
            parsed_endpoint.hostname
            and (
                parsed_endpoint.scheme == "https"
                or (parsed_endpoint.scheme == "http" and local_endpoint)
            )
        )
        checks.append(
            DoctorCheck(
                "object-store-endpoint",
                "pass" if endpoint_valid else "fail",
                (
                    "HTTPS or loopback HTTP endpoint"
                    if endpoint_valid
                    else "missing or unsafe endpoint"
                ),
                True,
            )
        )
        bucket = os.environ.get("RADAR_S3_BUCKET", "").strip()
        bucket_valid = 3 <= len(bucket) <= 63 and all(
            character.islower() or character.isdigit() or character in ".-"
            for character in bucket
        )
        checks.append(
            DoctorCheck(
                "object-store-bucket",
                "pass" if bucket_valid else "fail",
                "configured" if bucket_valid else "missing or invalid bucket name",
                True,
            )
        )
    if profile in {"portable", "production"}:
        from packages.security_gateway.deployment import (
            DeploymentApprovalError,
            require_deployment_approval,
        )

        approval_path = selected_config.parent / "deployment-approval.yaml"
        try:
            approval = require_deployment_approval(
                "collection",
                approval_path=approval_path,
            )
        except DeploymentApprovalError as exc:
            checks.append(DoctorCheck("deployment-approval", "fail", str(exc), True))
        else:
            checks.append(
                DoctorCheck(
                    "deployment-approval",
                    "pass",
                    f"valid until {approval['expires_at']}",
                    True,
                )
            )
    adapter = os.environ.get("RADAR_AGENT_ADAPTER", "codex")
    mode = os.environ.get("RADAR_AGENT_MODE", "plan")
    if mode != "plan":
        if adapter in {"openclaw", "codex", "claude"}:
            executable = os.environ.get("RADAR_AGENT_EXECUTABLE", adapter)
            available = shutil.which(executable) is not None
            checks.append(
                DoctorCheck(
                    "agent-runtime",
                    "pass" if available else "fail",
                    f"{adapter} command {'available' if available else 'not found'}",
                    True,
                )
            )
        elif adapter == "openai-compatible":
            status = inspect_secret("RADAR_AGENT_API_KEY")
            model = os.environ.get("RADAR_AGENT_MODEL", "").strip()
            configured = status.configured and bool(model)
            checks.append(
                DoctorCheck(
                    "agent-runtime",
                    "pass" if configured else "fail",
                    "HTTPS adapter configured" if configured else "model or API key missing",
                    True,
                )
            )
        elif adapter != "fixture":
            checks.append(DoctorCheck("agent-runtime", "fail", "unsupported adapter", True))
        if adapter != "fixture":
            pricing = (
                os.environ.get("RADAR_AGENT_INPUT_PRICE_PER_MILLION", "").strip(),
                os.environ.get("RADAR_AGENT_OUTPUT_PRICE_PER_MILLION", "").strip(),
            )
            checks.append(
                DoctorCheck(
                    "agent-pricing",
                    "pass" if all(pricing) else "warn",
                    (
                        "explicit token prices configured"
                        if all(pricing)
                        else "set input/output price per million for cost attribution"
                    ),
                    False,
                )
            )
    ready = all(check.status != "fail" for check in checks if check.required)
    return {
        "ready": ready,
        "profile": profile,
        "agent_mode": mode,
        "agent_adapter": adapter,
        "checks": [asdict(check) for check in checks],
    }


def _set_config_value(path: Path, name: str, value: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    replacement = f"{name}={value}"
    updated: list[str] = []
    replaced = False
    for line in lines:
        if line.split("=", 1)[0].strip() == name:
            if not replaced:
                updated.append(replacement)
                replaced = True
            continue
        updated.append(line)
    if not replaced:
        updated.append(replacement)
    path.write_text("\n".join(updated).rstrip() + "\n", encoding="utf-8")
    harden_private_path(path)
