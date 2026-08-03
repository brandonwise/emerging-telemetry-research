from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from apps.worker.entrypoint import _environment_files
from packages.onboarding.harnesses import (
    HarnessStatus,
    valid_harness_test_receipt,
    write_harness_test_receipt,
)


def test_entrypoint_layers_private_config_before_explicit_adapter(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(tmp_path)
    private = tmp_path / ".emerging-telemetry-research/config.env"
    private.parent.mkdir()
    private.write_text("ETR_AGENT_MODE=plan\n", encoding="utf-8")
    adapter = tmp_path / "research.env"
    adapter.write_text("ETR_AGENT_MODE=shadow\n", encoding="utf-8")

    files = _environment_files(("--env-file", str(adapter), "portable", "run"))

    assert files == (Path(".emerging-telemetry-research/config.env"), adapter)


def test_harness_receipt_expires_and_binds_runtime_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ETR_AGENT_MODEL", "approved-model")
    status = HarnessStatus(
        harness="codex",
        available=True,
        version="codex 1.2.3",
        authentication="unverified",
        detail="available",
        contract_test_required=True,
    )
    tested_at = datetime(2026, 8, 3, 12, tzinfo=UTC)
    receipt = write_harness_test_receipt(
        tmp_path / "codex.receipt.json",
        status=status,
        evaluation={"passed": True, "gates": {"schema": True}},
        tested_at=tested_at,
    )

    assert valid_harness_test_receipt(
        receipt,
        status=status,
        now=tested_at + timedelta(days=29),
    )
    assert not valid_harness_test_receipt(
        receipt,
        status=status,
        now=tested_at + timedelta(days=31),
    )
    monkeypatch.setenv("ETR_AGENT_MODEL", "different-model")
    assert not valid_harness_test_receipt(receipt, status=status, now=tested_at)
