from __future__ import annotations

import json
import os
import stat
from email.message import EmailMessage
from pathlib import Path
from typing import ClassVar

import pytest

from packages.common.canonical import canonical_json_bytes
from packages.delivery import email as email_delivery
from packages.delivery.email import (
    SmtpDeliverySettings,
    build_email_delivery_plan,
    send_email_delivery_plan,
)
from packages.pipeline.frozen import run_frozen_fixture


class FakeSmtp:
    instances: ClassVar[list[FakeSmtp]] = []

    def __init__(self, host: str, port: int, *, timeout: float) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.ehlo_count = 0
        self.started_tls = False
        self.login_value: tuple[str, str] | None = None
        self.sent: list[tuple[EmailMessage, str, list[str]]] = []
        self.instances.append(self)

    def __enter__(self) -> FakeSmtp:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def ehlo(self) -> None:
        self.ehlo_count += 1

    def starttls(self, *, context: object) -> None:
        assert context is not None
        self.started_tls = True

    def login(self, username: str, password: str) -> None:
        self.login_value = (username, password)

    def send_message(
        self,
        message: EmailMessage,
        *,
        from_addr: str,
        to_addrs: list[str],
    ) -> None:
        self.sent.append((message, from_addr, to_addrs))


def _email_plan(tmp_path: Path, recipient: str = "alerts@example.com") -> tuple[Path, Path]:
    run_root = tmp_path / "run"
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        run_root,
    )
    plan = build_email_delivery_plan(
        result.report,
        html_path=result.rendered.path,
        recipient=recipient,
    )
    plan_path = result.rendered.path.with_suffix(".delivery.json")
    plan_path.write_bytes(canonical_json_bytes(plan) + b"\n")
    return run_root, plan_path


def _settings(recipient: str = "alerts@example.com") -> SmtpDeliverySettings:
    return SmtpDeliverySettings(
        host="smtp.example.com",
        port=587,
        sender="threat-radar@example.com",
        recipient=recipient,
        security="starttls",
        username="smtp-user",
        password="smtp-password",  # noqa: S106
    )


def test_email_plan_is_deterministic_and_hides_recipient(tmp_path: Path) -> None:
    run_root, plan_path = _email_plan(tmp_path)
    plan = json.loads(plan_path.read_text(encoding="utf-8"))

    assert plan["destination"].startswith("email:recipient:")
    assert "alerts@example.com" not in json.dumps(plan)
    assert plan["subject"] == "Threat Radar Morning: 1 verified finding"
    assert plan["html_path"].startswith(str(run_root.resolve()))


def test_email_plan_rejects_invalid_recipient(tmp_path: Path) -> None:
    result = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        tmp_path / "run",
    )
    with pytest.raises(ValueError, match="email address is invalid"):
        build_email_delivery_plan(
            result.report,
            html_path=result.rendered.path,
            recipient="attacker@example.com\nBcc: victim@example.com",
        )


def test_smtp_sender_is_tls_fixed_recipient_and_retry_safe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeSmtp.instances.clear()
    monkeypatch.setattr(email_delivery.smtplib, "SMTP", FakeSmtp)
    run_root, plan_path = _email_plan(tmp_path)

    first = send_email_delivery_plan(
        plan_path,
        report_root=run_root,
        settings=_settings(),
    )
    second = send_email_delivery_plan(
        plan_path,
        report_root=run_root,
        settings=_settings(),
    )

    assert first["status"] == "delivered"
    assert first["duplicate"] is False
    assert second["duplicate"] is True
    assert len(FakeSmtp.instances) == 1
    client = FakeSmtp.instances[0]
    assert client.started_tls is True
    assert client.ehlo_count == 2
    assert client.login_value == ("smtp-user", "smtp-password")
    message, from_addr, to_addrs = client.sent[0]
    assert from_addr == "threat-radar@example.com"
    assert to_addrs == ["alerts@example.com"]
    assert message["X-Threat-Radar-Report-ID"]
    assert any(
        part.get_filename() and part.get_filename().endswith(".html")
        for part in message.walk()
    )
    receipt_path = next((run_root / ".delivery-receipts").glob("*.json"))
    if os.name != "nt":
        assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600


def test_sender_rejects_plan_for_different_fixed_recipient(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    FakeSmtp.instances.clear()
    monkeypatch.setattr(email_delivery.smtplib, "SMTP", FakeSmtp)
    run_root, plan_path = _email_plan(tmp_path)

    with pytest.raises(ValueError, match="configured recipient"):
        send_email_delivery_plan(
            plan_path,
            report_root=run_root,
            settings=_settings("other@example.com"),
        )

    assert FakeSmtp.instances == []


def test_unknown_smtp_outcome_refuses_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingSmtp(FakeSmtp):
        def send_message(
            self,
            message: EmailMessage,
            *,
            from_addr: str,
            to_addrs: list[str],
        ) -> None:
            del message, from_addr, to_addrs
            raise OSError("connection dropped")

    monkeypatch.setattr(email_delivery.smtplib, "SMTP", FailingSmtp)
    run_root, plan_path = _email_plan(tmp_path)
    with pytest.raises(OSError, match="connection dropped"):
        send_email_delivery_plan(
            plan_path,
            report_root=run_root,
            settings=_settings(),
        )

    with pytest.raises(ValueError, match="status is unknown"):
        send_email_delivery_plan(
            plan_path,
            report_root=run_root,
            settings=_settings(),
        )
