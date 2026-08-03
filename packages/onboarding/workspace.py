from __future__ import annotations

import os
import platform
import shutil
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

import yaml

if TYPE_CHECKING:
    from packages.security_gateway.deployment import DeploymentControlPaths

from packages.security_gateway.permissions import harden_private_path
from packages.security_gateway.secrets import (
    inspect_secret,
    keyring_reference,
    store_keyring_secret,
)

RESOURCE_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIRECTORY = ".emerging-telemetry-research"
DEFAULT_CONFIG = """# Emerging Telemetry Research local configuration.
# This private directory is ignored by Git.
# Store credentials with setup secret-set; only keyring references appear here.
ETR_CONFIG_SCHEMA_VERSION=1
ETR_PROFILE=portable
ETR_AGENT_MODE=plan
ETR_AGENT_ADAPTER=auto
ETR_AGENT_API_KEY_REF=
ETR_AGENT_INPUT_PRICE_PER_MILLION=
ETR_AGENT_OUTPUT_PRICE_PER_MILLION=
ETR_AGENT_PLUGIN_ALLOWLIST=
ETR_COLLECTOR_PLUGIN_ALLOWLIST=
BRAVE_API_KEY_REF=
XAI_API_KEY_REF=
ETR_DATABASE_URL_REF=
ETR_S3_ENDPOINT_URL=http://127.0.0.1:19000
ETR_S3_ACCESS_KEY_ID_REF=
ETR_S3_SECRET_ACCESS_KEY_REF=
ETR_S3_BUCKET=emerging-telemetry-research-evidence
ETR_S3_REGION=us-east-1
ETR_ANALYTICS_DB=state/research.db
ETR_OBJECT_ROOT=state/objects
ETR_REPORT_ROOT=reports/generated
ETR_MISSION_ROOT=.emerging-telemetry-research/missions
ETR_MISSION_REPORT_ROOT=reports/missions
ETR_MISSION_FEEDBACK_ROOT=reports/mission-feedback
ETR_DISCOVERY_CONFIG=.emerging-telemetry-research/config/discovery.yaml
ETR_SOURCES_CONFIG=.emerging-telemetry-research/config/sources.yaml
ETR_SOURCE_TERMS_CONFIG=.emerging-telemetry-research/config/source-terms.yaml
ETR_SCORING_CONFIG=.emerging-telemetry-research/config/scoring.yaml
ETR_MODELS_CONFIG=.emerging-telemetry-research/config/models.yaml
ETR_EMBEDDINGS_CONFIG=.emerging-telemetry-research/config/embeddings.yaml
EXTERNAL_DELIVERY_ENABLED=false
ETR_EMAIL_DELIVERY_ENABLED=false
ETR_PORTAL_MISSIONS_ROOT=.emerging-telemetry-research/missions
ETR_PORTAL_MISSION_REPORTS_ROOT=reports/missions
"""
PRIVATE_IGNORE = "*\n!.gitignore\n"
SECRET_GROUPS = {
    "portable": ("BRAVE_API_KEY", "XAI_API_KEY"),
    "production": (
        "BRAVE_API_KEY",
        "XAI_API_KEY",
        "ETR_DATABASE_URL",
        "ETR_S3_ACCESS_KEY_ID",
        "ETR_S3_SECRET_ACCESS_KEY",
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
SUPPORTED_AGENT_MODES = {"plan", "shadow", "active"}
SUPPORTED_AGENT_ADAPTERS = {
    "auto",
    "fixture",
    "openclaw",
    "codex",
    "claude",
    "openai-compatible",
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
    updated: list[str] = []
    for directory in (config_root, root / "state/objects", root / "reports/generated"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        harden_private_path(directory)
    files = {
        config_root / "config.env": DEFAULT_CONFIG,
        config_root / ".gitignore": PRIVATE_IGNORE,
    }
    for path, content in files.items():
        if path.exists() and not force:
            if path.name == "config.env" and _append_missing_config_defaults(path, content):
                updated.append(str(path))
            skipped.append(str(path))
            continue
        path.write_text(content, encoding="utf-8")
        harden_private_path(path)
        created.append(str(path))
    _set_config_value(config_root / "config.env", "ETR_PROFILE", profile)
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
        "updated": updated,
        "external_delivery": "disabled",
    }


def configure_keyring_credential(
    name: str,
    value: str,
    *,
    config_path: Path,
    service: str = "emerging-telemetry-research",
) -> None:
    reference = keyring_reference(name, service=service)
    store_keyring_secret(name, value, service=service)
    _set_config_value(config_path, f"{name}_REF", reference)


def configure_agent_runtime(
    *,
    config_path: Path,
    adapter: str,
    mode: str,
    model: str = "",
    base_url: str = "",
    provider_name: str = "",
) -> None:
    if adapter not in SUPPORTED_AGENT_ADAPTERS:
        raise ValueError("unsupported agent adapter")
    if mode not in SUPPORTED_AGENT_MODES:
        raise ValueError("unsupported agent mode")
    bounded = {
        "ETR_AGENT_ADAPTER": adapter,
        "ETR_AGENT_MODE": mode,
        "ETR_AGENT_MODEL": _single_line(model, maximum=200),
        "ETR_AGENT_PROVIDER_NAME": _single_line(provider_name, maximum=100),
    }
    clean_base_url = base_url.strip()
    if clean_base_url:
        parsed = urlsplit(clean_base_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("agent base URL must be credential-free HTTPS")
        if parsed.fragment:
            raise ValueError("agent base URL cannot include a fragment")
        bounded["ETR_AGENT_BASE_URL"] = clean_base_url.rstrip("/")
    elif adapter == "openai-compatible":
        raise ValueError("OpenAI-compatible adapters require an HTTPS base URL")
    for name, value in bounded.items():
        _set_config_value(config_path, name, value)


def run_doctor(
    *,
    profile: str = "core",
    config_path: Path | None = None,
    control_paths: DeploymentControlPaths | None = None,
) -> dict[str, object]:
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
        "integrations/templates/common/research.env.example",
        "fixtures/vertical_slice/early-manifest.json",
        "apps/setup/templates/index.html",
    )
    missing = [item for item in resources if not _resource_available(item)]
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
                "run `uv run emerging-telemetry-research setup init` to create local defaults",
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
        endpoint = os.environ.get("ETR_S3_ENDPOINT_URL", "").strip()
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
        bucket = os.environ.get("ETR_S3_BUCKET", "").strip()
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
            DeploymentControlPaths,
            require_deployment_approval,
        )

        approval_path = selected_config.parent / "deployment-approval.yaml"
        if control_paths is not None and not isinstance(
            control_paths,
            DeploymentControlPaths,
        ):
            raise ValueError("doctor control paths are invalid")
        try:
            approval = require_deployment_approval(
                "collection",
                approval_path=approval_path,
                paths=control_paths,
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
    adapter = os.environ.get("ETR_AGENT_ADAPTER", "auto")
    mode = os.environ.get("ETR_AGENT_MODE", "plan")
    if mode != "plan":
        from packages.onboarding.harnesses import (
            HarnessStatus,
            inspect_harnesses,
            valid_harness_test_receipt,
        )

        statuses = inspect_harnesses()
        candidates: tuple[HarnessStatus, ...]
        if adapter == "auto":
            candidates = tuple(
                item
                for item in statuses
                if item.harness in {"openclaw", "codex", "claude", "openai-compatible"}
                and item.available
            )
        else:
            candidates = tuple(
                item for item in statuses if item.harness == adapter and item.available
            )
        if adapter == "fixture":
            checks.append(
                DoctorCheck(
                    "agent-runtime",
                    "pass",
                    "deterministic fixture provider",
                    True,
                )
            )
        else:
            checks.append(
                DoctorCheck(
                    "agent-runtime",
                    "pass" if candidates else "fail",
                    (
                        "available: " + ", ".join(item.harness for item in candidates)
                        if candidates
                        else f"{adapter} harness is unavailable"
                    ),
                    True,
                )
            )
            certified = tuple(
                item
                for item in candidates
                if valid_harness_test_receipt(
                    selected_config.parent
                    / "harness-tests"
                    / f"{item.harness}.receipt.json",
                    status=item,
                )
            )
            checks.append(
                DoctorCheck(
                    "agent-contract-test",
                    "pass" if certified else "fail",
                    (
                        "certified: " + ", ".join(item.harness for item in certified)
                        if certified
                        else "run `uv run emerging-telemetry-research setup harness-test` "
                        "for the selected harness"
                    ),
                    True,
                )
            )
        if adapter != "fixture":
            pricing = (
                os.environ.get("ETR_AGENT_INPUT_PRICE_PER_MILLION", "").strip(),
                os.environ.get("ETR_AGENT_OUTPUT_PRICE_PER_MILLION", "").strip(),
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


def _single_line(value: str, *, maximum: int) -> str:
    normalized = value.strip()
    if len(normalized) > maximum or any(character in normalized for character in "\r\n\0"):
        raise ValueError("configuration value is invalid or too long")
    return normalized


def _append_missing_config_defaults(path: Path, defaults: str) -> bool:
    existing = path.read_text(encoding="utf-8")
    names = {
        line.split("=", 1)[0].strip()
        for line in existing.splitlines()
        if line.strip() and not line.lstrip().startswith("#") and "=" in line
    }
    additions = [
        line
        for line in defaults.splitlines()
        if line and not line.startswith("#") and line.split("=", 1)[0] not in names
    ]
    if not additions:
        return False
    content = (
        existing.rstrip()
        + "\n\n# Added by a compatible config upgrade.\n"
        + "\n".join(additions)
        + "\n"
    )
    path.write_text(content, encoding="utf-8")
    harden_private_path(path)
    return True


def _resource_available(relative: str) -> bool:
    if (RESOURCE_ROOT / relative).is_file():
        return True
    if relative.startswith("fixtures/"):
        return (RESOURCE_ROOT / "tests" / relative).is_file()
    return False
