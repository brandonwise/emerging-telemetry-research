from __future__ import annotations

from typing import Any

from packages.contracts.validation import parse_json_object, validate_payload

FORBIDDEN_EVIDENCE_KEYS = {
    "raw",
    "raw_artifact",
    "raw_content",
    "html",
    "response_body",
    "headers",
    "cookies",
    "authorization",
}


def validate_evidence_packet(packet: dict[str, Any]) -> None:
    validate_payload("evidence-packet.schema.json", packet)
    _reject_forbidden_keys(packet)


def parse_assessment(raw: str, allowed_evidence_ids: set[str]) -> dict[str, Any]:
    assessment = parse_json_object(raw, "assessment.schema.json")
    for claim in assessment["claims"]:
        referenced = set(claim["evidence_ids"])
        if not referenced.issubset(allowed_evidence_ids):
            raise ValueError("assessment references evidence outside its packet")
    return assessment


def validate_assessment(
    assessment: dict[str, Any],
    allowed_evidence_ids: set[str],
) -> None:
    validate_payload("assessment.schema.json", assessment)
    for claim in assessment["claims"]:
        if not set(claim["evidence_ids"]).issubset(allowed_evidence_ids):
            raise ValueError("assessment references evidence outside its packet")


def _reject_forbidden_keys(value: object) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in FORBIDDEN_EVIDENCE_KEYS:
                raise ValueError(f"raw or privileged field is forbidden: {key}")
            _reject_forbidden_keys(child)
    elif isinstance(value, list):
        for child in value:
            _reject_forbidden_keys(child)
