from __future__ import annotations

from datetime import datetime
from typing import Any

from packages.agents.contracts import validate_assessment, validate_evidence_packet
from packages.common.canonical import format_timestamp, stable_id


def run_shadow_review_chain(
    packet: dict[str, Any],
    *,
    created_at: datetime,
    recommended_disposition: str,
) -> tuple[dict[str, Any], ...]:
    """Deterministic fixture-only review chain used to test orchestration and replay."""
    validate_evidence_packet(packet)
    evidence_ids = {str(item["evidence_id"]) for item in packet["evidence"]}
    claims = [
        {
            "text": str(claim),
            "certainty": "observed",
            "evidence_ids": [str(item["evidence_id"])],
        }
        for item in packet["evidence"]
        for claim in item["claims_supported"][:1]
    ]
    independent = {
        str(item["independence_group"]) for item in packet["evidence"]
    }
    created = format_timestamp(created_at)
    cluster_id = str(packet["cluster_id"])
    assessments: list[dict[str, Any]] = []
    roles = ("specialist", "skeptic", "citation_verifier", "coordinator")
    for role in roles:
        uncertainties = []
        contradictions: list[str] = []
        judgment = {
            "specialist": (
                "The evidence supports continued monitoring and bounded defensive review."
            ),
            "skeptic": "Source lineage and chronology were checked for duplicate amplification.",
            "citation_verifier": (
                "Each proposed factual claim maps to an evidence item in the packet."
            ),
            "coordinator": "The deterministic score and verified evidence support the disposition.",
        }[role]
        if role == "skeptic" and len(independent) < 2:
            uncertainties.append("The cluster has fewer than two independent source origins.")
        assessment = {
            "schema_version": "1.0",
            "assessment_id": stable_id("as", cluster_id, role, created),
            "cluster_id": cluster_id,
            "agent_role": role,
            "created_at": created,
            "model": "deterministic-shadow-fixture",
            "prompt_revision": "shadow-v1",
            "judgment": judgment,
            "claims": claims,
            "uncertainties": uncertainties,
            "contradictions": contradictions,
            "recommended_disposition": recommended_disposition,
            "requested_followups": [],
        }
        validate_assessment(assessment, evidence_ids)
        assessments.append(assessment)
    return tuple(assessments)
