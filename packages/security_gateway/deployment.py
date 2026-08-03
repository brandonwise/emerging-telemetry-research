from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from packages.common.resources import BUNDLED_ROOT, configured_path
from packages.security_gateway.permissions import harden_private_path

OFFICIAL_SOURCE_IDS = {
    "cisa-kev",
    "cve-list-v5",
    "first-epss",
    "github-advisories",
    "nvd-cve",
    "osv",
}
SURFACE_SOURCE_IDS = {"reddit-security-web", "tiktok-security"}
CAPABILITIES = {"collection", "external_delivery", "self_improvement_apply"}


class DeploymentApprovalError(ValueError):
    """Raised when deployment authority is absent, expired, or stale."""


@dataclass(frozen=True, slots=True)
class DeploymentControlPaths:
    discovery: Path
    sources: Path
    source_terms: Path


def default_control_paths() -> DeploymentControlPaths:
    return DeploymentControlPaths(
        discovery=configured_path("ETR_DISCOVERY_CONFIG", "config/discovery.yaml"),
        sources=configured_path("ETR_SOURCES_CONFIG", "config/sources.yaml"),
        source_terms=configured_path("ETR_SOURCE_TERMS_CONFIG", "config/source-terms.yaml"),
    )


def create_approval_request(
    *,
    environment_id: str,
    paths: DeploymentControlPaths | None = None,
    allow_external_delivery: bool = False,
    allow_self_improvement_apply: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not environment_id.strip() or len(environment_id) > 200:
        raise DeploymentApprovalError("environment ID is empty or too long")
    controls = paths or default_control_paths()
    source_ids = validate_collection_controls(controls)
    created_at = (now or datetime.now(UTC)).astimezone(UTC)
    return {
        "schema_version": "1.0",
        "status": "approval_required",
        "environment_id": environment_id.strip(),
        "created_at": _timestamp(created_at),
        "control_hash": deployment_control_hash(controls),
        "source_ids": sorted(source_ids),
        "capabilities": {
            "collection": True,
            "external_delivery": allow_external_delivery,
            "self_improvement_apply": allow_self_improvement_apply,
        },
    }


def apply_approval_request(
    request: dict[str, Any],
    *,
    approved_by: str,
    approval_id: str,
    expires_days: int = 30,
    paths: DeploymentControlPaths | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    controls = paths or default_control_paths()
    _validate_request(request, controls)
    if not approved_by.strip() or len(approved_by) > 200:
        raise DeploymentApprovalError("approver identity is empty or too long")
    if not approval_id.strip() or len(approval_id) > 300:
        raise DeploymentApprovalError("approval ID is empty or too long")
    if not 1 <= expires_days <= 365:
        raise DeploymentApprovalError("approval expiry must be between 1 and 365 days")
    approved_at = (now or datetime.now(UTC)).astimezone(UTC)
    return {
        "schema_version": "1.0",
        "status": "approved",
        "environment_id": request["environment_id"],
        "approved_by": approved_by.strip(),
        "approval_id": approval_id.strip(),
        "approved_at": _timestamp(approved_at),
        "expires_at": _timestamp(approved_at + timedelta(days=expires_days)),
        "control_hash": request["control_hash"],
        "source_ids": request["source_ids"],
        "capabilities": request["capabilities"],
    }


def require_deployment_approval(
    capability: str,
    *,
    approval_path: Path | None = None,
    paths: DeploymentControlPaths | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    if capability not in CAPABILITIES:
        raise DeploymentApprovalError("unknown deployment capability")
    controls = paths or default_control_paths()
    path = approval_path or Path(
        os.environ.get(
            "ETR_DEPLOYMENT_APPROVAL",
            ".emerging-telemetry-research/deployment-approval.yaml",
        )
    )
    approval = _load_object(path, "deployment approval")
    if approval.get("status") != "approved":
        raise DeploymentApprovalError("deployment approval is not approved")
    _validate_common(approval)
    expires_at = _parse_timestamp(approval.get("expires_at"), "expires_at")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if current >= expires_at:
        raise DeploymentApprovalError("deployment approval has expired")
    expected_hash = deployment_control_hash(controls)
    actual_hash = str(approval.get("control_hash", ""))
    if not hmac.compare_digest(actual_hash, expected_hash):
        raise DeploymentApprovalError("deployment controls changed after approval")
    current_sources = sorted(validate_collection_controls(controls))
    if approval.get("source_ids") != current_sources:
        raise DeploymentApprovalError("approved source set does not match runtime source set")
    capabilities = approval.get("capabilities")
    if not isinstance(capabilities, dict) or capabilities.get(capability) is not True:
        raise DeploymentApprovalError(f"deployment approval does not grant {capability}")
    return approval


def deployment_control_hash(paths: DeploymentControlPaths) -> str:
    digest = hashlib.sha256()
    selected = {
        "config/discovery.yaml": paths.discovery,
        "config/source-terms.yaml": paths.source_terms,
        "config/sources.yaml": paths.sources,
    }
    for root_name in ("apps", "packages", "policies", "schemas"):
        root = BUNDLED_ROOT / root_name
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            if path.suffix not in {".py", ".yaml", ".json"}:
                continue
            selected[str(path.relative_to(BUNDLED_ROOT))] = path
    for name in ("SECURITY.md", "THREAT_MODEL.md"):
        path = BUNDLED_ROOT / name
        if path.is_file():
            selected[name] = path
    for label, path in sorted(selected.items()):
        if not path.is_file():
            raise DeploymentApprovalError(f"protected deployment input is missing: {label}")
        content = path.read_bytes()
        digest.update(label.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def validate_collection_controls(paths: DeploymentControlPaths) -> set[str]:
    discovery = _load_yaml(paths.discovery, "discovery configuration")
    sources = _load_yaml(paths.sources, "source configuration")
    terms = _load_yaml(paths.source_terms, "source terms")
    required = set(OFFICIAL_SOURCE_IDS)
    brave = discovery.get("brave")
    if not isinstance(brave, dict) or not isinstance(brave.get("queries"), list):
        raise DeploymentApprovalError("discovery configuration has no Brave queries")
    if brave["queries"]:
        required.add("brave-web")
    for query in brave["queries"]:
        if isinstance(query, dict) and query.get("source_id") in SURFACE_SOURCE_IDS:
            required.add(str(query["source_id"]))
    x_search = discovery.get("x_search")
    if not isinstance(x_search, dict) or not x_search.get("allowed_handles"):
        raise DeploymentApprovalError("discovery configuration has no approved X handles")
    required.add("x-researchers")
    reddit = discovery.get("reddit")
    if isinstance(reddit, dict) and reddit.get("enabled") is True:
        required.add("reddit-security")
    tiktok = discovery.get("tiktok_research")
    if isinstance(tiktok, dict) and tiktok.get("enabled") is True:
        required.add("tiktok-research")
    source_items = sources.get("sources")
    if not isinstance(source_items, list):
        raise DeploymentApprovalError("source configuration has no source list")
    enabled = {
        str(item.get("id"))
        for item in source_items
        if isinstance(item, dict) and item.get("enabled") is True
    }
    missing = sorted(required - enabled)
    if missing:
        raise DeploymentApprovalError("runtime sources are not enabled: " + ", ".join(missing))
    term_items = terms.get("sources")
    if not isinstance(term_items, dict):
        raise DeploymentApprovalError("source terms configuration has no source records")
    unapproved = sorted(
        source_id
        for source_id in required
        if not isinstance(term_items.get(source_id), dict)
        or term_items[source_id].get("status") != "approved"
    )
    if unapproved:
        raise DeploymentApprovalError(
            "runtime source terms are not approved: " + ", ".join(unapproved)
        )
    return required


def write_private_yaml(path: Path, value: dict[str, Any]) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    harden_private_path(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            yaml.safe_dump(value, handle, sort_keys=False)
        harden_private_path(temporary)
        temporary.replace(path)
        harden_private_path(path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return path


def write_private_json(path: Path, value: dict[str, Any]) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    harden_private_path(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
        harden_private_path(temporary)
        temporary.replace(path)
        harden_private_path(path)
    finally:
        if temporary.exists():
            temporary.unlink()
    return path


def _validate_request(request: dict[str, Any], paths: DeploymentControlPaths) -> None:
    if request.get("status") != "approval_required":
        raise DeploymentApprovalError("deployment request is not approval-ready")
    _validate_common(request)
    expected_hash = deployment_control_hash(paths)
    if not hmac.compare_digest(str(request.get("control_hash", "")), expected_hash):
        raise DeploymentApprovalError("deployment controls changed after the request")
    if request.get("source_ids") != sorted(validate_collection_controls(paths)):
        raise DeploymentApprovalError("deployment source set changed after the request")


def _validate_common(value: dict[str, Any]) -> None:
    if value.get("schema_version") != "1.0":
        raise DeploymentApprovalError("unsupported deployment approval schema")
    if not isinstance(value.get("environment_id"), str) or not value["environment_id"]:
        raise DeploymentApprovalError("deployment approval has no environment ID")
    source_ids = value.get("source_ids")
    if not isinstance(source_ids, list) or not source_ids or not all(
        isinstance(item, str) and item for item in source_ids
    ):
        raise DeploymentApprovalError("deployment approval source list is invalid")
    capabilities = value.get("capabilities")
    if not isinstance(capabilities, dict) or set(capabilities) != CAPABILITIES:
        raise DeploymentApprovalError("deployment approval capabilities are invalid")
    if not all(isinstance(item, bool) for item in capabilities.values()):
        raise DeploymentApprovalError("deployment approval capabilities must be booleans")


def _load_yaml(path: Path, label: str) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise DeploymentApprovalError(f"{label} is unavailable or invalid") from exc
    if not isinstance(value, dict):
        raise DeploymentApprovalError(f"{label} must be an object")
    return value


def _load_object(path: Path, label: str) -> dict[str, Any]:
    return _load_yaml(path, label)


def _parse_timestamp(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise DeploymentApprovalError(f"deployment approval {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DeploymentApprovalError(f"deployment approval {label} is invalid") from exc
    if parsed.tzinfo is None:
        raise DeploymentApprovalError(f"deployment approval {label} needs a timezone")
    return parsed.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
