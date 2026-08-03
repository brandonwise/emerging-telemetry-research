from __future__ import annotations

from typing import Any

from packages.contracts.validation import validate_payload
from packages.missions.compiler import MissionDefinition


def evaluate_mission_report(
    mission: MissionDefinition,
    report: dict[str, Any],
    *,
    feedback: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    validate_payload("mission-report.schema.json", report)
    evaluation = mission.payload["evaluation"]
    outcomes = report["outcomes"]
    labels = [
        item
        for item in (feedback or [])
        if item.get("mission_id") == mission.mission_id
        and item.get("report_id") == report["report_id"]
    ]
    if labels:
        for item in labels:
            validate_payload("mission-feedback.schema.json", item)
        latest_by_outcome = {
            str(item["outcome_id"]): item
            for item in sorted(labels, key=lambda value: str(value["submitted_at"]))
        }
        useful_count = sum(item["label"] == "useful" for item in latest_by_outcome.values())
        useful_rate = useful_count / len(latest_by_outcome)
        usefulness_basis = "analyst_feedback"
    else:
        useful = [item for item in outcomes if item["priority_class"] != "archive"]
        useful_rate = len(useful) / len(outcomes) if outcomes else 0.0
        usefulness_basis = "priority_proxy"
    source_types = {
        str(source["source_type"])
        for outcome in outcomes
        for source in outcome["source_evidence"]
    }
    all_claims_cited = all(
        bool(claim["evidence_ids"])
        for outcome in outcomes
        for claim in outcome["claims"]
    )
    checks = {
        "report_contract": True,
        "mission_matches": report["mission_id"] == mission.mission_id,
        "all_claims_cited": all_claims_cited,
        "maximum_evidence_age_enforced": report["verification"][
            "maximum_evidence_age_enforced"
        ],
        "minimum_source_diversity": (
            len(source_types) >= int(evaluation["minimum_source_diversity"])
        ),
        "minimum_useful_outcome_rate": (
            useful_rate >= float(evaluation["minimum_useful_outcome_rate"])
        ),
        "code_owned_ranking": report["verification"]["code_owned_ranking"] is True,
        "external_delivery_disabled": mission.payload["governance"][
            "external_delivery_enabled"
        ]
        is False,
    }
    return {
        "schema_version": "1.0",
        "mission_id": mission.mission_id,
        "report_id": report["report_id"],
        "passed": all(checks.values()),
        "checks": checks,
        "metrics": {
            "outcome_count": len(outcomes),
            "useful_outcome_rate": round(useful_rate, 4),
            "source_diversity": len(source_types),
            "success_metric": evaluation["success_metric"],
            "usefulness_basis": usefulness_basis,
            "feedback_count": len(labels),
        },
    }
