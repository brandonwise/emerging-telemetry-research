from __future__ import annotations

import hashlib
import json
import os
import re
import smtplib
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path
from typing import Any, Literal, cast

from packages.common.canonical import canonical_json_bytes, stable_id
from packages.contracts.validation import validate_payload
from packages.security_gateway.permissions import harden_private_path
from packages.security_gateway.secrets import resolve_secret
from packages.verification.claims import require_verified_report

EMAIL_ADDRESS = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


@dataclass(frozen=True, slots=True)
class SmtpDeliverySettings:
    host: str
    port: int
    sender: str
    recipient: str
    security: Literal["ssl", "starttls"] = "starttls"
    username: str | None = None
    password: str | None = field(default=None, repr=False)
    timeout_seconds: float = 30.0

    @classmethod
    def from_env(cls) -> SmtpDeliverySettings:
        security = os.environ.get("ETR_SMTP_SECURITY", "starttls").lower()
        if security not in {"ssl", "starttls"}:
            raise ValueError("ETR_SMTP_SECURITY must be ssl or starttls")
        try:
            port = int(os.environ.get("ETR_SMTP_PORT", "587"))
            timeout_seconds = float(os.environ.get("ETR_SMTP_TIMEOUT_SECONDS", "30"))
        except ValueError as exc:
            raise ValueError("SMTP port and timeout must be numeric") from exc
        return cls(
            host=_required_env("ETR_SMTP_HOST"),
            port=port,
            sender=_required_env("ETR_EMAIL_SENDER"),
            recipient=_required_env("ETR_EMAIL_RECIPIENT"),
            security=cast(Literal["ssl", "starttls"], security),
            username=os.environ.get("ETR_SMTP_USERNAME") or None,
            password=resolve_secret("ETR_SMTP_PASSWORD", required=False),
            timeout_seconds=timeout_seconds,
        )

    def validate(self) -> None:
        if self.security not in {"ssl", "starttls"}:
            raise ValueError("SMTP security must be ssl or starttls")
        if not self.host or any(character.isspace() for character in self.host):
            raise ValueError("SMTP host is invalid")
        if not 1 <= self.port <= 65535:
            raise ValueError("SMTP port must be between 1 and 65535")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 120:
            raise ValueError("SMTP timeout must be between 0 and 120 seconds")
        _normalize_email_address(self.sender)
        _normalize_email_address(self.recipient)
        if (self.username is None) != (self.password is None):
            raise ValueError("SMTP username and password must be configured together")


def build_email_delivery_plan(
    report: dict[str, Any],
    *,
    html_path: Path,
    recipient: str,
) -> dict[str, Any]:
    require_verified_report(report)
    normalized_recipient = _normalize_email_address(recipient)
    destination = email_delivery_destination(normalized_recipient)
    findings = report.get("findings", [])
    if findings:
        lines = [
            f"{item['publication_class'].upper()} {item['priority_score']:.1f} — {item['title']}"
            for item in findings[:5]
        ]
        summary = "\n".join(lines)
    else:
        summary = "No material emerging threats met the publication threshold."
    report_id = str(report["report_id"])
    edition = str(report.get("edition", "report")).replace("_", " ").title()
    finding_label = "finding" if len(findings) == 1 else "findings"
    subject = f"Telemetry Research {edition}: {len(findings)} verified {finding_label}"
    plan = {
        "schema_version": "1.0",
        "delivery_id": stable_id("dl", report_id, destination),
        "report_id": report_id,
        "destination": destination,
        "idempotency_key": stable_id(
            "idem",
            report_id,
            destination,
            canonical_json_bytes(report).decode("utf-8"),
            length=48,
        ),
        "subject": subject[:200],
        "summary": summary[:2000],
        "html_path": str(html_path.resolve()),
    }
    validate_payload("delivery.schema.json", plan)
    return plan


def send_email_delivery_plan(
    plan_path: Path,
    *,
    report_root: Path,
    settings: SmtpDeliverySettings,
) -> dict[str, Any]:
    """Send a verified, fixed-recipient plan and persist a fail-closed receipt."""
    settings.validate()
    root = report_root.resolve(strict=True)
    resolved_plan_path = plan_path.resolve(strict=True)
    if not resolved_plan_path.is_relative_to(root):
        raise ValueError("delivery plan is outside the configured report root")
    plan = _read_json_object(resolved_plan_path, "delivery plan")
    validate_payload("delivery.schema.json", plan)
    html_path = Path(str(plan["html_path"])).resolve(strict=True)
    if not html_path.is_relative_to(root) or html_path.suffix != ".html":
        raise ValueError("report HTML is outside the configured report root")
    if resolved_plan_path != html_path.with_suffix(".delivery.json"):
        raise ValueError("delivery plan path does not match report HTML")
    if not html_path.is_file() or html_path.stat().st_size > 10_485_760:
        raise ValueError("report HTML is invalid")
    report = _read_json_object(html_path.with_suffix(".json"), "report")
    require_verified_report(report)
    expected = build_email_delivery_plan(
        report,
        html_path=html_path,
        recipient=settings.recipient,
    )
    if plan != expected:
        raise ValueError("delivery plan does not match the configured recipient and report")

    receipt_directory = root / ".delivery-receipts"
    receipt_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt_path = receipt_directory / f"{plan['idempotency_key']}.json"
    existing = _read_optional_receipt(receipt_path)
    if existing is not None:
        _validate_existing_receipt(existing, plan)
        return {**existing, "duplicate": True}

    pending = {
        "status": "pending",
        "report_id": plan["report_id"],
        "destination": plan["destination"],
        "idempotency_key": plan["idempotency_key"],
        "created_at": datetime.now(UTC).isoformat(),
    }
    try:
        with receipt_path.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(pending, separators=(",", ":"), sort_keys=True) + "\n")
        harden_private_path(receipt_path)
    except FileExistsError:
        raced = _read_optional_receipt(receipt_path)
        if raced is None:
            raise ValueError("delivery receipt disappeared during creation") from None
        _validate_existing_receipt(raced, plan)
        return {**raced, "duplicate": True}

    message_id = f"<{plan['idempotency_key']}@telemetry-research.invalid>"
    message = EmailMessage()
    message["Subject"] = str(plan["subject"])
    message["From"] = _normalize_email_address(settings.sender)
    message["To"] = _normalize_email_address(settings.recipient)
    message["Date"] = format_datetime(datetime.now(UTC))
    message["Message-ID"] = message_id
    message["X-Threat-Research-Report-ID"] = str(plan["report_id"])
    message.set_content(str(plan["summary"]))
    message.add_attachment(
        html_path.read_bytes(),
        maintype="text",
        subtype="html",
        filename=f"{plan['report_id']}.html",
    )
    _send_smtp(message, settings)

    receipt = {
        "status": "delivered",
        "report_id": plan["report_id"],
        "destination": plan["destination"],
        "idempotency_key": plan["idempotency_key"],
        "message_id": message_id,
        "delivered_at": datetime.now(UTC).isoformat(),
    }
    staged_path = receipt_path.with_name(
        f"{receipt_path.name}.{os.getpid()}.{datetime.now(UTC).timestamp():.0f}.tmp"
    )
    with staged_path.open("x", encoding="utf-8") as handle:
        handle.write(json.dumps(receipt, separators=(",", ":"), sort_keys=True) + "\n")
    harden_private_path(staged_path)
    staged_path.replace(receipt_path)
    return {**receipt, "duplicate": False}


def _send_smtp(message: EmailMessage, settings: SmtpDeliverySettings) -> None:
    context = ssl.create_default_context()
    if settings.security == "ssl":
        client: smtplib.SMTP = smtplib.SMTP_SSL(
            settings.host,
            settings.port,
            timeout=settings.timeout_seconds,
            context=context,
        )
    else:
        client = smtplib.SMTP(
            settings.host,
            settings.port,
            timeout=settings.timeout_seconds,
        )
    with client:
        if settings.security == "starttls":
            client.ehlo()
            client.starttls(context=context)
            client.ehlo()
        if settings.username is not None and settings.password is not None:
            client.login(settings.username, settings.password)
        client.send_message(
            message,
            from_addr=_normalize_email_address(settings.sender),
            to_addrs=[_normalize_email_address(settings.recipient)],
        )


def email_delivery_destination(recipient: str) -> str:
    normalized_recipient = _normalize_email_address(recipient)
    digest = hashlib.sha256(normalized_recipient.encode("utf-8")).hexdigest()
    return f"email:recipient:{digest}"


def _normalize_email_address(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) > 254 or not EMAIL_ADDRESS.fullmatch(normalized):
        raise ValueError("email address is invalid")
    return normalized


def _required_env(name: str) -> str:
    value = resolve_secret(name)
    if value is None:
        raise ValueError(f"{name} is required")
    return value


def _read_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _read_optional_receipt(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return _read_json_object(path, "delivery receipt")


def _validate_existing_receipt(receipt: dict[str, Any], plan: dict[str, Any]) -> None:
    matches = all(
        receipt.get(field) == plan[field]
        for field in ("report_id", "destination", "idempotency_key")
    )
    if not matches:
        raise ValueError("delivery idempotency conflict")
    if receipt.get("status") != "delivered":
        raise ValueError("delivery status is unknown; refusing a possible duplicate")
