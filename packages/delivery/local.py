from __future__ import annotations

from pathlib import Path
from typing import Any

from packages.common.canonical import canonical_json_bytes, stable_id
from packages.contracts.validation import validate_payload
from packages.verification.claims import require_verified_report


def build_local_delivery_plan(
    report: dict[str, Any],
    *,
    html_path: Path,
) -> dict[str, Any]:
    """Build an immutable file-only plan for vendor-neutral deployments."""
    require_verified_report(report)
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
    destination = "file:local"
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
        "summary": summary[:2000],
        "html_path": str(html_path.resolve()),
    }
    validate_payload("delivery.schema.json", plan)
    return plan
