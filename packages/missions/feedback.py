from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packages.common.canonical import format_timestamp, stable_id
from packages.contracts.validation import validate_payload
from packages.missions.compiler import MissionDefinition

FEEDBACK_LABELS = ("useful", "not_useful", "needs_work")


def record_mission_feedback(
    mission: MissionDefinition,
    report: dict[str, Any],
    *,
    outcome_id: str,
    label: str,
    reason: str,
    submitted_by: str,
    output_root: Path,
    submitted_at: datetime | None = None,
) -> tuple[dict[str, Any], Path]:
    validate_payload("mission-report.schema.json", report)
    if report["mission_id"] != mission.mission_id:
        raise ValueError("report does not belong to this mission")
    if label not in FEEDBACK_LABELS:
        raise ValueError("feedback label must be useful, not_useful, or needs_work")
    if outcome_id not in {str(item["outcome_id"]) for item in report["outcomes"]}:
        raise ValueError("outcome does not exist in the report")
    clean_reason = " ".join(reason.split())
    clean_submitter = " ".join(submitted_by.split())
    if not 3 <= len(clean_reason) <= 1200:
        raise ValueError("feedback reason must contain 3-1200 characters")
    if not 2 <= len(clean_submitter) <= 120:
        raise ValueError("submitted_by must contain 2-120 characters")
    when = submitted_at or datetime.now(UTC)
    if when.tzinfo is None:
        raise ValueError("submitted_at must include a timezone")
    timestamp = format_timestamp(when)
    feedback_id = stable_id(
        "mf",
        mission.mission_id,
        str(report["report_id"]),
        outcome_id,
        label,
        clean_submitter,
        timestamp,
    )
    payload = {
        "schema_version": "1.0",
        "feedback_id": feedback_id,
        "mission_id": mission.mission_id,
        "report_id": report["report_id"],
        "outcome_id": outcome_id,
        "label": label,
        "reason": clean_reason,
        "submitted_by": clean_submitter,
        "submitted_at": timestamp,
    }
    validate_payload("mission-feedback.schema.json", payload)
    destination = output_root.resolve() / mission.mission_id / f"{feedback_id}.json"
    if destination.exists():
        existing = json.loads(destination.read_text(encoding="utf-8"))
        if existing != payload:
            raise ValueError("feedback ID collision")
        return payload, destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return payload, destination


def load_mission_feedback(root: Path, mission_id: str) -> list[dict[str, Any]]:
    mission_root = (root / mission_id).resolve()
    if root.resolve() not in mission_root.parents or not mission_root.is_dir():
        return []
    feedback: list[dict[str, Any]] = []
    for path in sorted(mission_root.glob("mf_*.json")):
        value = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"feedback file is not an object: {path}")
        validate_payload("mission-feedback.schema.json", value)
        feedback.append(value)
    return feedback
