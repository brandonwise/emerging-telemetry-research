from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from packages.common.canonical import canonical_json_bytes, format_timestamp, sha256_hex, stable_id
from packages.contracts.validation import validate_payload


@dataclass(frozen=True, slots=True)
class AdvisorySettings:
    minimum_feedback: int
    maximum_missing_source_rate: float
    maximum_negative_feedback_rate: float
    maximum_degraded_source_rate: float
    maximum_agent_failure_rate: float
    maximum_estimated_currency_per_report: float

    @classmethod
    def load(cls, path: Path) -> AdvisorySettings:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("advisory"), dict):
            raise ValueError("improvement advisory configuration is missing")
        advisory = value["advisory"]
        settings = cls(
            minimum_feedback=int(advisory["minimum_feedback"]),
            maximum_missing_source_rate=float(advisory["maximum_missing_source_rate"]),
            maximum_negative_feedback_rate=float(advisory["maximum_negative_feedback_rate"]),
            maximum_degraded_source_rate=float(advisory["maximum_degraded_source_rate"]),
            maximum_agent_failure_rate=float(advisory["maximum_agent_failure_rate"]),
            maximum_estimated_currency_per_report=float(
                advisory["maximum_estimated_currency_per_report"]
            ),
        )
        rates = (
            settings.maximum_missing_source_rate,
            settings.maximum_negative_feedback_rate,
            settings.maximum_degraded_source_rate,
            settings.maximum_agent_failure_rate,
        )
        if settings.minimum_feedback < 1 or any(not 0 <= item <= 1 for item in rates):
            raise ValueError("improvement advisory gates are invalid")
        if settings.maximum_estimated_currency_per_report < 0:
            raise ValueError("improvement advisory cost gate is invalid")
        return settings


def run_advisory_cycle(
    *,
    reports_root: Path,
    feedback_root: Path,
    mission_feedback_root: Path,
    output_root: Path,
    improvement_config: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    settings = AdvisorySettings.load(improvement_config)
    metrics = _collect_metrics(reports_root, feedback_root, mission_feedback_root)
    generated_at = (now or datetime.now(UTC)).astimezone(UTC)
    cycle_id = stable_id(
        "ia",
        format_timestamp(generated_at),
        sha256_hex(canonical_json_bytes(metrics)),
    )
    proposals = _proposals(cycle_id, metrics, settings)
    result = {
        "schema_version": "1.0",
        "cycle_id": cycle_id,
        "generated_at": format_timestamp(generated_at),
        "status": "approval_required" if proposals else "no_change",
        "metrics": metrics,
        "proposals": proposals,
        "automatic_apply": False,
        "protected_boundaries": [
            "source_terms",
            "deployment_approval",
            "external_delivery",
            "security_policies",
            "hard_budget_limits",
        ],
    }
    validate_payload("improvement-advice.schema.json", result)
    destination = output_root / cycle_id / "improvement-advice.json"
    _write_immutable(destination, canonical_json_bytes(result) + b"\n")
    return {**result, "advice_path": str(destination.resolve())}


def _collect_metrics(
    reports_root: Path,
    feedback_root: Path,
    mission_feedback_root: Path,
) -> dict[str, Any]:
    reports_by_id: dict[str, dict[str, Any]] = {}
    if reports_root.exists():
        for path in sorted(reports_root.rglob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict) or not isinstance(value.get("report_id"), str):
                continue
            if not isinstance(value.get("findings"), list) and not isinstance(
                value.get("outcomes"), list
            ):
                continue
            reports_by_id[str(value["report_id"])] = value
    reports = list(reports_by_id.values())
    source_checks = 0
    degraded_sources = 0
    agent_reviews = 0
    agent_failures = 0
    contradictions = 0
    injection_events = 0
    estimated_currency = 0.0
    for report in reports:
        for source in report.get("source_health", []):
            if not isinstance(source, dict):
                continue
            source_checks += 1
            status = str(source.get("status", "")).lower()
            if source.get("available") is False or status in {"degraded", "failed", "disabled"}:
                degraded_sources += 1
        for review in report.get("agent_reviews", []):
            if not isinstance(review, dict):
                continue
            agent_reviews += 1
            if review.get("status") != "completed" or review.get("failures"):
                agent_failures += 1
            for assessment in review.get("assessments", []):
                if isinstance(assessment, dict) and assessment.get("contradictions"):
                    contradictions += 1
        for usage in report.get("usage", []):
            if isinstance(usage, dict) and isinstance(usage.get("estimated_currency"), int | float):
                estimated_currency += float(usage["estimated_currency"])
        for finding in report.get("findings", []):
            if not isinstance(finding, dict):
                continue
            for evidence in finding.get("source_evidence", []):
                if isinstance(evidence, dict) and evidence.get("injection_risk") in {
                    "high",
                    "critical",
                }:
                    injection_events += 1
    feedback_counts: Counter[str] = Counter()
    if feedback_root.exists():
        for path in sorted(feedback_root.rglob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(value, dict) and isinstance(value.get("taxonomy"), str):
                feedback_counts[str(value["taxonomy"])] += 1
    if mission_feedback_root.exists():
        for path in sorted(mission_feedback_root.rglob("*.json")):
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(value, dict) and value.get("label") in {
                "useful",
                "not_useful",
                "needs_work",
            }:
                feedback_counts[f"mission:{value['label']}"] += 1
    feedback_count = sum(feedback_counts.values())
    negative_count = sum(
        feedback_counts[item]
        for item in (
            "correct_but_low_relevance",
            "duplicate_syndicated",
            "incorrect_interpretation",
            "unsupported_certainty",
            "overstated_impact",
            "understated_impact",
            "mission:not_useful",
            "mission:needs_work",
        )
    )
    return {
        "report_count": len(reports),
        "feedback_count": feedback_count,
        "missing_source_rate": _rate(
            feedback_counts["missing_material_source"], feedback_count
        ),
        "negative_feedback_rate": _rate(negative_count, feedback_count),
        "degraded_source_rate": _rate(degraded_sources, source_checks),
        "agent_failure_rate": _rate(agent_failures, agent_reviews),
        "agent_contradiction_count": contradictions,
        "injection_event_count": injection_events,
        "estimated_currency_per_report": round(
            estimated_currency / len(reports), 6
        ) if reports else 0.0,
    }


def _proposals(
    cycle_id: str,
    metrics: dict[str, Any],
    settings: AdvisorySettings,
) -> list[dict[str, Any]]:
    candidates: list[tuple[str, str, str, list[str]]] = []
    enough_feedback = int(metrics["feedback_count"]) >= settings.minimum_feedback
    if enough_feedback and metrics["missing_source_rate"] > settings.maximum_missing_source_rate:
        candidates.append(
            (
                "source_coverage",
                "Draft additional approved source/query coverage for the missing-material labels.",
                "missing_source_rate",
                ["fixture replay", "source diversity", "terms review", "deployment reapproval"],
            )
        )
    if (
        enough_feedback
        and metrics["negative_feedback_rate"] > settings.maximum_negative_feedback_rate
    ):
        candidates.append(
            (
                "calibration",
                "Evaluate a bounded scoring calibration challenger against labeled outcomes.",
                "negative_feedback_rate",
                ["precision", "recall regression", "false-alert regression", "human approval"],
            )
        )
    if metrics["degraded_source_rate"] > settings.maximum_degraded_source_rate:
        candidates.append(
            (
                "source_reliability",
                "Review source timeouts, retry policy, circuit state, and a tested fallback.",
                "degraded_source_rate",
                ["chaos test", "freshness SLO", "fallback provenance"],
            )
        )
    if metrics["agent_failure_rate"] > settings.maximum_agent_failure_rate:
        candidates.append(
            (
                "routing",
                "Evaluate provider fallback order and model capability routing in shadow mode.",
                "agent_failure_rate",
                ["schema compliance", "latency", "cost", "cross-provider stability"],
            )
        )
    if metrics["agent_contradiction_count"]:
        candidates.append(
            (
                "prompt",
                "Draft a versioned prompt challenger focused on unresolved contradictions.",
                "agent_contradiction_count",
                ["citation coverage", "disposition agreement", "injection corpus"],
            )
        )
    if metrics["estimated_currency_per_report"] > settings.maximum_estimated_currency_per_report:
        candidates.append(
            (
                "cost",
                "Evaluate cheaper routes for noncritical roles while preserving quality gates.",
                "estimated_currency_per_report",
                ["quality non-regression", "budget reserve", "flash-path isolation"],
            )
        )
    if metrics["injection_event_count"]:
        candidates.append(
            (
                "security",
                "Quarantine affected samples and run sanitizer/parser regression challengers.",
                "injection_event_count",
                ["zero privileged effects", "zero secret exposure", "parser isolation"],
            )
        )
    return [
        {
            "proposal_id": stable_id("iap", cycle_id, domain),
            "domain": domain,
            "status": "approval_required",
            "trigger_metric": metric,
            "observed_value": float(metrics[metric]),
            "recommendation": recommendation,
            "required_evaluations": evaluations,
            "automatic_apply": False,
        }
        for domain, recommendation, metric, evaluations in candidates
    ]


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _write_immutable(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError(f"immutable advice conflict: {path}")
        return
    with path.open("xb") as handle:
        handle.write(content)
