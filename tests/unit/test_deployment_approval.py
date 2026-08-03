from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from packages.onboarding.workspace import PORTABLE_SOURCE_IDS, initialize_workspace
from packages.security_gateway.deployment import (
    DeploymentApprovalError,
    DeploymentControlPaths,
    apply_approval_request,
    create_approval_request,
    require_deployment_approval,
    write_private_yaml,
)


def _controls(root: Path) -> DeploymentControlPaths:
    config = root / ".emerging-telemetry-research/config"
    return DeploymentControlPaths(
        discovery=config / "discovery.yaml",
        sources=config / "sources.yaml",
        source_terms=config / "source-terms.yaml",
    )


def test_portable_init_prepares_sources_without_granting_authority(tmp_path: Path) -> None:
    initialize_workspace(tmp_path, profile="portable")
    sources = yaml.safe_load(
        (tmp_path / ".emerging-telemetry-research/config/sources.yaml").read_text(encoding="utf-8")
    )
    enabled = {
        str(item["id"])
        for item in sources["sources"]
        if item.get("enabled") is True
    }

    assert enabled == PORTABLE_SOURCE_IDS
    assert not (tmp_path / ".emerging-telemetry-research/deployment-approval.yaml").exists()


def test_approval_is_expiring_capability_and_control_bound(tmp_path: Path) -> None:
    initialize_workspace(tmp_path, profile="portable")
    controls = _controls(tmp_path)
    approved_at = datetime(2026, 8, 3, 12, tzinfo=UTC)
    request = create_approval_request(
        environment_id="test-host",
        paths=controls,
        now=approved_at,
    )
    approval = apply_approval_request(
        request,
        approved_by="test-operator",
        approval_id="review-123",
        expires_days=7,
        paths=controls,
        now=approved_at,
    )
    approval_path = write_private_yaml(
        tmp_path / ".emerging-telemetry-research/deployment-approval.yaml",
        approval,
    )

    loaded = require_deployment_approval(
        "collection",
        approval_path=approval_path,
        paths=controls,
        now=approved_at + timedelta(days=1),
    )

    assert loaded["approval_id"] == "review-123"
    if os.name != "nt":
        assert approval_path.stat().st_mode & 0o077 == 0
    with pytest.raises(DeploymentApprovalError, match="does not grant external_delivery"):
        require_deployment_approval(
            "external_delivery",
            approval_path=approval_path,
            paths=controls,
            now=approved_at + timedelta(days=1),
        )
    with pytest.raises(DeploymentApprovalError, match="expired"):
        require_deployment_approval(
            "collection",
            approval_path=approval_path,
            paths=controls,
            now=approved_at + timedelta(days=8),
        )


def test_approval_invalidates_when_a_protected_input_changes(tmp_path: Path) -> None:
    initialize_workspace(tmp_path, profile="portable")
    controls = _controls(tmp_path)
    approved_at = datetime(2026, 8, 3, 12, tzinfo=UTC)
    request = create_approval_request(
        environment_id="test-host",
        paths=controls,
        now=approved_at,
    )
    approval = apply_approval_request(
        request,
        approved_by="test-operator",
        approval_id="review-123",
        paths=controls,
        now=approved_at,
    )
    approval_path = write_private_yaml(tmp_path / "approval.yaml", approval)
    controls.discovery.write_text(
        controls.discovery.read_text(encoding="utf-8") + "\n# changed after review\n",
        encoding="utf-8",
    )

    with pytest.raises(DeploymentApprovalError, match="changed after approval"):
        require_deployment_approval(
            "collection",
            approval_path=approval_path,
            paths=controls,
            now=approved_at + timedelta(hours=1),
        )


def test_distributable_source_defaults_cannot_request_collection() -> None:
    controls = DeploymentControlPaths(
        discovery=Path("config/discovery.yaml"),
        sources=Path("config/sources.yaml"),
        source_terms=Path("config/source-terms.yaml"),
    )

    with pytest.raises(DeploymentApprovalError, match="not enabled"):
        create_approval_request(environment_id="unsafe-default", paths=controls)
