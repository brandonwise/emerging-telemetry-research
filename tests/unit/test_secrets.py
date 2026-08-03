from __future__ import annotations

import os
from pathlib import Path

import pytest

from packages.onboarding import workspace as onboarding_workspace
from packages.onboarding.environment import load_environment_file, parse_environment_file
from packages.onboarding.workspace import initialize_workspace, run_doctor
from packages.security_gateway.secrets import (
    SecretResolutionError,
    inspect_secret,
    keyring_reference,
    resolve_secret,
    store_keyring_secret,
)


class MemoryKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service_name: str, username: str) -> str | None:
        return self.values.get((service_name, username))

    def set_password(self, service_name: str, username: str, password: str) -> None:
        self.values[(service_name, username)] = password


def test_secret_resolution_supports_direct_environment_and_indirection() -> None:
    keyring = MemoryKeyring()
    keyring.values[("outcome-radar", "BRAVE_API_KEY")] = "stored-brave-value"

    assert resolve_secret("BRAVE_API_KEY", environ={"BRAVE_API_KEY": "direct"}) == "direct"
    assert (
        resolve_secret(
            "BRAVE_API_KEY",
            environ={
                "BRAVE_API_KEY_REF": "env://PRIVATE_BRAVE_KEY",
                "PRIVATE_BRAVE_KEY": "indirect",
            },
        )
        == "indirect"
    )
    assert (
        resolve_secret(
            "BRAVE_API_KEY",
            environ={"BRAVE_API_KEY_REF": "keyring://outcome-radar/BRAVE_API_KEY"},
            keyring_backend=keyring,
        )
        == "stored-brave-value"
    )


def test_secret_resolution_fails_closed_on_ambiguity_and_self_reference() -> None:
    with pytest.raises(SecretResolutionError, match="cannot both"):
        resolve_secret(
            "BRAVE_API_KEY",
            environ={
                "BRAVE_API_KEY": "direct",
                "BRAVE_API_KEY_REF": "env://PRIVATE_BRAVE_KEY",
            },
        )


def test_secret_resolution_supports_owner_only_file_references(tmp_path: Path) -> None:
    secret = tmp_path / "api-key"
    secret.write_text("file-backed-value\n", encoding="utf-8")
    secret.chmod(0o600)

    assert resolve_secret(
        "BRAVE_API_KEY",
        environ={"BRAVE_API_KEY_REF": secret.as_uri()},
    ) == "file-backed-value"

    if secret.stat().st_mode & 0o077 == 0:
        secret.chmod(0o644)
        with pytest.raises(SecretResolutionError, match="owner-only"):
            resolve_secret(
                "BRAVE_API_KEY",
                environ={"BRAVE_API_KEY_REF": secret.as_uri()},
            )
    with pytest.raises(SecretResolutionError, match="cannot reference itself"):
        resolve_secret(
            "BRAVE_API_KEY",
            environ={"BRAVE_API_KEY_REF": "env://BRAVE_API_KEY"},
        )


def test_keyring_storage_is_separate_from_non_secret_reference() -> None:
    keyring = MemoryKeyring()
    result = store_keyring_secret(
        "XAI_API_KEY",
        "never-print-this",
        keyring_backend=keyring,
    )
    reference = keyring_reference("XAI_API_KEY")

    assert result is None
    assert reference == "keyring://outcome-radar/XAI_API_KEY"
    assert "never-print-this" not in reference
    assert inspect_secret(
        "XAI_API_KEY",
        environ={"XAI_API_KEY_REF": reference},
        keyring_backend=keyring,
    ).configured


def test_environment_file_is_data_not_shell(tmp_path: Path) -> None:
    path = tmp_path / "radar.env"
    path.write_text(
        "RADAR_AGENT_MODE=plan\nPRIVATE_BRAVE_KEY=$(touch should-not-run)\n",
        encoding="utf-8",
    )
    target: dict[str, str] = {}

    loaded = load_environment_file(path, environ=target)

    assert loaded == ("RADAR_AGENT_MODE", "PRIVATE_BRAVE_KEY")
    assert target["PRIVATE_BRAVE_KEY"] == "$(touch should-not-run)"
    assert not (tmp_path / "should-not-run").exists()


def test_environment_file_rejects_duplicates(tmp_path: Path) -> None:
    path = tmp_path / "radar.env"
    path.write_text("BRAVE_API_KEY=one\nBRAVE_API_KEY=two\n", encoding="utf-8")

    with pytest.raises(ValueError, match="repeats BRAVE_API_KEY"):
        parse_environment_file(path)


def test_workspace_init_is_private_and_idempotent(tmp_path: Path) -> None:
    first = initialize_workspace(tmp_path)
    second = initialize_workspace(tmp_path)
    config = tmp_path / ".outcome-radar/config.env"

    assert config.is_file()
    if os.name != "nt":
        assert config.stat().st_mode & 0o077 == 0
    assert first["created"]
    assert second["created"] == []
    assert second["skipped"]


def test_configure_keyring_secret_writes_only_reference(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = tmp_path / ".outcome-radar/config.env"
    initialize_workspace(tmp_path)
    monkeypatch.setattr(
        onboarding_workspace,
        "store_keyring_secret",
        lambda name, value, service: f"keyring://{service}/{name}",
    )

    onboarding_workspace.configure_keyring_credential(
        "BRAVE_API_KEY",
        "never-write-this",
        config_path=config,
    )

    content = config.read_text(encoding="utf-8")
    assert keyring_reference("BRAVE_API_KEY") in content
    assert "never-write-this" not in content


def test_core_doctor_reports_runtime_readiness(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RADAR_AGENT_MODE", "plan")

    result = run_doctor(profile="core")

    assert result["ready"] is True
    assert all("value" not in str(check).lower() for check in result["checks"])
