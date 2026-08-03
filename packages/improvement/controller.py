from __future__ import annotations

import json
import os
import re
import tempfile
from collections import Counter
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from packages.common.canonical import (
    canonical_json_bytes,
    format_timestamp,
    parse_timestamp,
    sha256_hex,
    stable_id,
)
from packages.contracts.validation import validate_payload
from packages.evaluation.harness import run_acceptance_suite
from packages.scoring.engine import PublicationThresholds, load_thresholds
from packages.workflow.checkpoints import SQLiteCheckpointStore
from packages.workflow.graph import GraphNode, execute_graph

POSITIVE_TAXONOMIES = {
    "actionable_and_early",
    "actionable_but_already_known",
    "useful_watch_not_alert",
}
NEGATIVE_TAXONOMIES = {
    "correct_but_low_relevance",
    "duplicate_syndicated",
    "incorrect_interpretation",
    "unsupported_certainty",
    "overstated_impact",
    "understated_impact",
}
NON_LABEL_TAXONOMIES = {
    "missing_material_source",
    "injection_manipulation_suspected",
}
ALL_TAXONOMIES = POSITIVE_TAXONOMIES | NEGATIVE_TAXONOMIES | NON_LABEL_TAXONOMIES
DAILY_THRESHOLD_PATH = "thresholds.daily"
SCORING_TARGET = "config/scoring.yaml"


@dataclass(frozen=True, slots=True)
class ImprovementSettings:
    minimum_labeled_findings: int
    minimum_positive_findings: int
    minimum_negative_findings: int
    minimum_precision: float
    maximum_recall_regression: float
    maximum_false_alert_regression: float
    minimum_utility_gain: float
    maximum_missing_source_rate: float
    daily_minimum: float
    daily_maximum: float
    daily_step: float
    precision_weight: float
    recall_weight: float
    false_alert_weight: float

    @classmethod
    def load(cls, path: Path) -> ImprovementSettings:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("improvement configuration must be an object")
        gates = _mapping(value, "gates")
        mutable = _mapping(value, "mutable_parameters")
        daily = _mapping(mutable, DAILY_THRESHOLD_PATH)
        objective = _mapping(value, "objective")
        settings = cls(
            minimum_labeled_findings=int(gates["minimum_labeled_findings"]),
            minimum_positive_findings=int(gates["minimum_positive_findings"]),
            minimum_negative_findings=int(gates["minimum_negative_findings"]),
            minimum_precision=float(gates["minimum_precision"]),
            maximum_recall_regression=float(gates["maximum_recall_regression"]),
            maximum_false_alert_regression=float(
                gates["maximum_false_alert_regression"]
            ),
            minimum_utility_gain=float(gates["minimum_utility_gain"]),
            maximum_missing_source_rate=float(gates["maximum_missing_source_rate"]),
            daily_minimum=float(daily["minimum"]),
            daily_maximum=float(daily["maximum"]),
            daily_step=float(daily["step"]),
            precision_weight=float(objective["precision_weight"]),
            recall_weight=float(objective["recall_weight"]),
            false_alert_weight=float(objective["false_alert_weight"]),
        )
        settings.validate()
        return settings

    def validate(self) -> None:
        if min(
            self.minimum_labeled_findings,
            self.minimum_positive_findings,
            self.minimum_negative_findings,
        ) < 0:
            raise ValueError("improvement sample gates cannot be negative")
        bounded = (
            self.minimum_precision,
            self.maximum_recall_regression,
            self.maximum_false_alert_regression,
            self.minimum_utility_gain,
            self.maximum_missing_source_rate,
            self.precision_weight,
            self.recall_weight,
            self.false_alert_weight,
        )
        if any(not 0 <= value <= 1 for value in bounded):
            raise ValueError("improvement rates and weights must be inside [0, 1]")
        if not 0 <= self.daily_minimum < self.daily_maximum < 65:
            raise ValueError("mutable daily threshold must remain below the frozen watch threshold")
        if self.daily_step <= 0:
            raise ValueError("daily threshold step must be positive")


def record_feedback(
    *,
    report_path: Path,
    finding_id: str,
    taxonomy: str,
    submitted_by: str,
    output_root: Path,
    notes: str | None = None,
    now: datetime | None = None,
) -> tuple[dict[str, Any], Path]:
    if taxonomy not in ALL_TAXONOMIES:
        raise ValueError("unsupported analyst feedback taxonomy")
    report = _json_object(report_path)
    report_id = str(report.get("report_id", ""))
    if not report_id.startswith("rp_"):
        raise ValueError("feedback target is not a report")
    finding_ids = {
        str(item.get("finding_id"))
        for item in report.get("findings", [])
        if isinstance(item, dict)
    }
    if taxonomy not in NON_LABEL_TAXONOMIES and finding_id not in finding_ids:
        raise ValueError("feedback finding does not exist in the report")
    if not re.fullmatch(r"fd_[A-Za-z0-9_-]+", finding_id):
        raise ValueError("invalid finding ID")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,100}", submitted_by):
        raise ValueError("invalid feedback submitter")
    created_at = (now or datetime.now(UTC)).astimezone(UTC)
    feedback_id = stable_id(
        "fb",
        report_id,
        finding_id,
        taxonomy,
        submitted_by,
        format_timestamp(created_at),
    )
    feedback = {
        "schema_version": "1.0",
        "feedback_id": feedback_id,
        "report_id": report_id,
        "finding_id": finding_id,
        "taxonomy": taxonomy,
        "notes": notes,
        "submitted_by": submitted_by,
        "created_at": format_timestamp(created_at),
    }
    validate_payload("analyst-feedback.schema.json", feedback)
    path = output_root / f"{feedback_id}.json"
    _write_immutable(path, canonical_json_bytes(feedback) + b"\n")
    return feedback, path


def run_improvement_cycle(
    *,
    reports_root: Path,
    feedback_root: Path,
    output_root: Path,
    fixture_root: Path,
    scoring_config: Path,
    improvement_config: Path,
    now: datetime | None = None,
) -> dict[str, Any]:
    requested_at = (now or datetime.now(UTC)).astimezone(UTC)
    settings = ImprovementSettings.load(improvement_config)
    thresholds = load_thresholds(scoring_config)
    if not settings.daily_minimum <= thresholds.daily <= settings.daily_maximum:
        raise ValueError("active daily threshold is outside the improvement policy bounds")
    scoring_bytes = scoring_config.read_bytes()
    feedback_hash = _directory_hash(feedback_root)
    reports_hash = _directory_hash(reports_root, pattern="rp_*.json")
    cycle_id = stable_id(
        "ic",
        sha256_hex(scoring_bytes),
        feedback_hash,
        reports_hash,
    )
    cycle_root = output_root / cycle_id
    cycle_metadata_path = cycle_root / "cycle-metadata.json"
    if cycle_metadata_path.is_file():
        cycle_metadata = _json_object(cycle_metadata_path)
        generated_at = parse_timestamp(str(cycle_metadata["generated_at"]))
    else:
        generated_at = requested_at
        _write_immutable(
            cycle_metadata_path,
            canonical_json_bytes(
                {
                    "schema_version": "1.0",
                    "cycle_id": cycle_id,
                    "generated_at": format_timestamp(generated_at),
                    "input_hashes": {
                        "scoring": sha256_hex(scoring_bytes),
                        "feedback": feedback_hash,
                        "reports": reports_hash,
                    },
                }
            )
            + b"\n",
        )
    snapshot_path = cycle_root / "snapshots" / "scoring.yaml"

    def snapshot(_outputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
        _write_immutable(snapshot_path, scoring_bytes)
        return {
            "target_path": SCORING_TARGET,
            "snapshot_path": str(snapshot_path.resolve()),
            "sha256": sha256_hex(scoring_bytes),
            "daily_threshold": thresholds.daily,
            "protected": [
                "thresholds.flash",
                "thresholds.watch",
                "hard_rules",
                "confirmation_rules",
                "source_terms",
                "delivery_boundary",
            ],
        }

    def observe(_outputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
        return _observe(reports_root, feedback_root)

    def acceptance(_outputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
        result = run_acceptance_suite(
            fixture_root,
            cycle_root / "acceptance",
            scoring_config=scoring_config,
        )
        return {
            "passed": result["passed"],
            "gates": result["gates"],
            "artifact_sha256": sha256_hex(canonical_json_bytes(result)),
        }

    def evaluator(threshold: float) -> Any:
        def evaluate(outputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
            samples = _samples(outputs["observe"])
            return _metrics(samples, threshold, settings)

        return evaluate

    candidate_thresholds = _candidate_thresholds(thresholds, settings)
    evaluation_node_ids = tuple(
        f"evaluate_{_threshold_slug(value)}" for value in candidate_thresholds
    )

    def select(outputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
        return _select(
            observe=outputs["observe"],
            acceptance=outputs["acceptance"],
            baseline=outputs["evaluate_baseline"],
            challengers=[outputs[node_id] for node_id in evaluation_node_ids],
            current_threshold=thresholds.daily,
            settings=settings,
        )

    nodes = (
        GraphNode("snapshot", (), snapshot),
        GraphNode("observe", ("snapshot",), observe),
        GraphNode("acceptance", ("snapshot",), acceptance),
        GraphNode("evaluate_baseline", ("observe",), evaluator(thresholds.daily)),
        *(
            GraphNode(
                node_id,
                ("observe",),
                evaluator(candidate_threshold),
            )
            for node_id, candidate_threshold in zip(
                evaluation_node_ids,
                candidate_thresholds,
                strict=True,
            )
        ),
        GraphNode(
            "select",
            ("acceptance", "evaluate_baseline", *evaluation_node_ids),
            select,
        ),
    )
    execution = execute_graph(
        nodes,
        maximum_parallel_nodes=4,
        workflow_id=cycle_id,
        checkpoint_store=SQLiteCheckpointStore(cycle_root / "checkpoints.db"),
    )
    selection = execution.outputs["select"]
    proposal_path: Path | None = None
    proposal: dict[str, Any] | None = None
    if selection["status"] == "approval_required":
        selected_threshold = float(selection["selected"]["threshold"])
        proposal = {
            "schema_version": "1.0",
            "proposal_id": stable_id(
                "ip",
                cycle_id,
                DAILY_THRESHOLD_PATH,
                str(selected_threshold),
            ),
            "cycle_id": cycle_id,
            "status": "approval_required",
            "target_path": SCORING_TARGET,
            "base_sha256": sha256_hex(scoring_bytes),
            "changes": [
                {
                    "path": DAILY_THRESHOLD_PATH,
                    "from": thresholds.daily,
                    "to": selected_threshold,
                }
            ],
            "reason": selection["reason"],
            "baseline_metrics": selection["baseline"],
            "challenger_metrics": selection["selected"],
            "safety_anchor_sha256": execution.outputs["acceptance"]["artifact_sha256"],
            "rollback": {
                "snapshot_path": str(snapshot_path.resolve()),
                "expected_base_sha256": sha256_hex(scoring_bytes),
            },
            "automatic_apply": False,
            "created_at": format_timestamp(generated_at),
        }
        validate_payload("improvement-proposal.schema.json", proposal)
        proposal_path = cycle_root / "improvement-proposal.json"
        _write_immutable(proposal_path, canonical_json_bytes(proposal) + b"\n")

    result = {
        "schema_version": "1.0",
        "cycle_id": cycle_id,
        "generated_at": format_timestamp(generated_at),
        "status": selection["status"],
        "stop_reason": selection["reason"],
        "graph": execution.manifest,
        "loop": {
            "shape": "observe_evaluate_challenge_verify_approve",
            "cadence": "weekly",
            "automatic_apply": False,
            "next_iteration_uses": "new analyst feedback and immutable production reports",
        },
        "anchors": {
            "acceptance_passed": execution.outputs["acceptance"]["passed"],
            "acceptance_sha256": execution.outputs["acceptance"]["artifact_sha256"],
            "scoring_snapshot_sha256": sha256_hex(scoring_bytes),
        },
        "observation": execution.outputs["observe"],
        "baseline": selection["baseline"],
        "challengers": selection["challengers"],
        "proposal_id": proposal["proposal_id"] if proposal else None,
        "proposal_path": str(proposal_path.resolve()) if proposal_path else None,
    }
    cycle_path = cycle_root / "improvement-cycle.json"
    _write_immutable(cycle_path, canonical_json_bytes(result) + b"\n")
    return {**result, "cycle_path": str(cycle_path.resolve())}


def apply_proposal(
    proposal_path: Path,
    *,
    repo_root: Path,
    approved_by: str,
    approval_id: str,
) -> dict[str, Any]:
    proposal = _json_object(proposal_path)
    validate_payload("improvement-proposal.schema.json", proposal)
    if proposal["status"] != "approval_required" or proposal["automatic_apply"] is not False:
        raise ValueError("proposal is not eligible for an approval-gated apply")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,100}", approved_by):
        raise ValueError("invalid approver")
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,128}", approval_id):
        raise ValueError("invalid approval ID")
    if proposal["target_path"] != SCORING_TARGET:
        raise ValueError("proposal targets a protected or unknown file")
    changes = proposal["changes"]
    if not isinstance(changes, list) or len(changes) != 1:
        raise ValueError("proposal must contain exactly one bounded change")
    change = changes[0]
    if not isinstance(change, dict) or change.get("path") != DAILY_THRESHOLD_PATH:
        raise ValueError("proposal attempts to change a protected policy")
    target = (repo_root / SCORING_TARGET).resolve()
    expected_target = (repo_root.resolve() / SCORING_TARGET).resolve()
    if target != expected_target or not target.is_file():
        raise ValueError("scoring target is invalid")
    before = target.read_bytes()
    if sha256_hex(before) != proposal["base_sha256"]:
        raise ValueError("scoring policy changed after the proposal was evaluated")
    current_thresholds = load_thresholds(target)
    previous = float(change["from"])
    updated = float(change["to"])
    if current_thresholds.daily != previous:
        raise ValueError("proposal baseline threshold no longer matches")
    if abs(updated - previous) > 5 or not 40 <= updated <= 60:
        raise ValueError("proposal exceeds the bounded daily-threshold mutation policy")

    rollback_path = proposal_path.parent / "rollback" / "scoring.yaml"
    _write_immutable(rollback_path, before)
    after = _replace_daily_threshold(before, updated)
    _atomic_write(target, after)
    receipt = {
        "schema_version": "1.0",
        "proposal_id": proposal["proposal_id"],
        "approval_id": approval_id,
        "approved_by": approved_by,
        "target_path": SCORING_TARGET,
        "previous_sha256": sha256_hex(before),
        "applied_sha256": sha256_hex(after),
        "rollback_path": str(rollback_path.resolve()),
        "status": "applied",
        "applied_at": format_timestamp(datetime.now(UTC)),
    }
    receipt_path = proposal_path.parent / "apply-receipt.json"
    _write_immutable(receipt_path, canonical_json_bytes(receipt) + b"\n")
    return {**receipt, "receipt_path": str(receipt_path.resolve())}


def rollback_proposal(
    receipt_path: Path,
    *,
    repo_root: Path,
    approved_by: str,
    approval_id: str,
) -> dict[str, Any]:
    receipt = _json_object(receipt_path)
    if receipt.get("status") != "applied" or receipt.get("target_path") != SCORING_TARGET:
        raise ValueError("receipt is not rollback eligible")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{1,100}", approved_by):
        raise ValueError("invalid rollback approver")
    if not re.fullmatch(r"[A-Za-z0-9_-]{3,128}", approval_id):
        raise ValueError("invalid rollback approval ID")
    target = (repo_root.resolve() / SCORING_TARGET).resolve()
    current = target.read_bytes()
    if sha256_hex(current) != receipt["applied_sha256"]:
        raise ValueError("scoring policy changed after the proposal was applied")
    rollback_path = Path(str(receipt["rollback_path"])).resolve()
    if (
        not rollback_path.is_relative_to(receipt_path.parent.resolve())
        or not rollback_path.is_file()
    ):
        raise ValueError("rollback snapshot is invalid")
    restored = rollback_path.read_bytes()
    if sha256_hex(restored) != receipt["previous_sha256"]:
        raise ValueError("rollback snapshot hash mismatch")
    _atomic_write(target, restored)
    result = {
        "schema_version": "1.0",
        "proposal_id": receipt["proposal_id"],
        "approval_id": approval_id,
        "approved_by": approved_by,
        "restored_sha256": sha256_hex(restored),
        "status": "rolled_back",
        "rolled_back_at": format_timestamp(datetime.now(UTC)),
    }
    output = receipt_path.parent / "rollback-receipt.json"
    _write_immutable(output, canonical_json_bytes(result) + b"\n")
    return {**result, "receipt_path": str(output.resolve())}


def _observe(reports_root: Path, feedback_root: Path) -> dict[str, Any]:
    reports: dict[str, dict[str, Any]] = {}
    findings: dict[tuple[str, str], dict[str, Any]] = {}
    if reports_root.exists():
        for path in sorted(reports_root.rglob("rp_*.json")):
            if not _eligible_report_path(path, reports_root):
                continue
            value = _json_object(path)
            report_id = value.get("report_id")
            if not isinstance(report_id, str):
                continue
            reports[report_id] = value
            for item in value.get("findings", []):
                if not isinstance(item, dict):
                    continue
                finding_id = item.get("finding_id")
                score = item.get("priority_score")
                if isinstance(finding_id, str) and isinstance(score, int | float):
                    findings[(report_id, finding_id)] = item

    latest: dict[tuple[str, str], dict[str, Any]] = {}
    taxonomy_counts: Counter[str] = Counter()
    feedback_count = 0
    if feedback_root.exists():
        for path in sorted(feedback_root.glob("fb_*.json")):
            value = _json_object(path)
            validate_payload("analyst-feedback.schema.json", value)
            feedback_count += 1
            taxonomy = str(value["taxonomy"])
            taxonomy_counts[taxonomy] += 1
            key = (str(value["report_id"]), str(value["finding_id"]))
            existing = latest.get(key)
            if existing is None or (
                str(value["created_at"]),
                str(value["feedback_id"]),
            ) > (
                str(existing["created_at"]),
                str(existing["feedback_id"]),
            ):
                latest[key] = value

    samples: list[dict[str, Any]] = []
    orphan_feedback = 0
    for key, feedback in sorted(latest.items()):
        taxonomy = str(feedback["taxonomy"])
        if taxonomy in NON_LABEL_TAXONOMIES:
            continue
        finding = findings.get(key)
        if finding is None:
            orphan_feedback += 1
            continue
        samples.append(
            {
                "report_id": key[0],
                "finding_id": key[1],
                "priority_score": float(finding["priority_score"]),
                "positive": taxonomy in POSITIVE_TAXONOMIES,
                "taxonomy": taxonomy,
            }
        )
    missing_sources = taxonomy_counts["missing_material_source"]
    security_flags = taxonomy_counts["injection_manipulation_suspected"]
    return {
        "report_count": len(reports),
        "finding_count": len(findings),
        "feedback_count": feedback_count,
        "labeled_finding_count": len(samples),
        "positive_count": sum(1 for item in samples if item["positive"]),
        "negative_count": sum(1 for item in samples if not item["positive"]),
        "missing_material_source_count": missing_sources,
        "missing_material_source_rate": (
            round(missing_sources / feedback_count, 6) if feedback_count else 0.0
        ),
        "security_review_required": security_flags > 0,
        "orphan_feedback_count": orphan_feedback,
        "taxonomy_counts": dict(sorted(taxonomy_counts.items())),
        "samples": samples,
    }


def _metrics(
    samples: list[dict[str, Any]],
    threshold: float,
    settings: ImprovementSettings,
) -> dict[str, Any]:
    positives = sum(1 for item in samples if bool(item["positive"]))
    negatives = len(samples) - positives
    predicted = [item for item in samples if float(item["priority_score"]) >= threshold]
    true_positive = sum(1 for item in predicted if bool(item["positive"]))
    false_positive = len(predicted) - true_positive
    false_negative = positives - true_positive
    precision = true_positive / len(predicted) if predicted else 0.0
    recall = true_positive / positives if positives else 0.0
    false_alert_rate = false_positive / negatives if negatives else 0.0
    utility = (
        settings.precision_weight * precision
        + settings.recall_weight * recall
        - settings.false_alert_weight * false_alert_rate
    )
    return {
        "threshold": threshold,
        "sample_count": len(samples),
        "predicted_count": len(predicted),
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "false_alert_rate": round(false_alert_rate, 6),
        "utility": round(utility, 6),
    }


def _select(
    *,
    observe: dict[str, Any],
    acceptance: dict[str, Any],
    baseline: dict[str, Any],
    challengers: list[dict[str, Any]],
    current_threshold: float,
    settings: ImprovementSettings,
) -> dict[str, Any]:
    result = {
        "baseline": baseline,
        "challengers": challengers,
        "selected": None,
    }
    if acceptance["passed"] is not True:
        return {
            **result,
            "status": "blocked",
            "reason": "frozen acceptance anchor failed",
        }
    if observe["security_review_required"] is True:
        return {
            **result,
            "status": "blocked",
            "reason": "analyst feedback requires a security review",
        }
    if observe["orphan_feedback_count"] > 0:
        return {
            **result,
            "status": "blocked",
            "reason": "analyst feedback contains unknown report or finding references",
        }
    if (
        observe["labeled_finding_count"] < settings.minimum_labeled_findings
        or observe["positive_count"] < settings.minimum_positive_findings
        or observe["negative_count"] < settings.minimum_negative_findings
    ):
        return {
            **result,
            "status": "insufficient_evidence",
            "reason": "minimum labeled positive and negative sample gates are not met",
        }
    eligible: list[dict[str, Any]] = []
    for challenger in challengers:
        threshold = float(challenger["threshold"])
        if (
            challenger["precision"] < settings.minimum_precision
            or challenger["recall"]
            < baseline["recall"] - settings.maximum_recall_regression
            or challenger["false_alert_rate"]
            > baseline["false_alert_rate"] + settings.maximum_false_alert_regression
            or challenger["utility"]
            < baseline["utility"] + settings.minimum_utility_gain
        ):
            continue
        if (
            threshold > current_threshold
            and observe["missing_material_source_rate"]
            > settings.maximum_missing_source_rate
        ):
            continue
        eligible.append(challenger)
    if not eligible:
        return {
            **result,
            "status": "no_change",
            "reason": "no bounded challenger beat the champion without counter-metric regression",
        }
    selected = max(
        eligible,
        key=lambda item: (
            float(item["utility"]),
            float(item["precision"]),
            float(item["recall"]),
            -abs(float(item["threshold"]) - current_threshold),
        ),
    )
    return {
        **result,
        "status": "approval_required",
        "reason": (
            "bounded daily threshold challenger improved multi-metric utility while "
            "preserving the frozen safety anchors"
        ),
        "selected": selected,
    }


def _candidate_thresholds(
    current: PublicationThresholds,
    settings: ImprovementSettings,
) -> tuple[float, ...]:
    values = {
        max(settings.daily_minimum, current.daily - settings.daily_step),
        min(settings.daily_maximum, current.daily + settings.daily_step),
    }
    values.discard(current.daily)
    return tuple(sorted(values))


def _samples(observation: dict[str, Any]) -> list[dict[str, Any]]:
    value = observation.get("samples")
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError("observation samples are invalid")
    return value


def _threshold_slug(value: float) -> str:
    return str(value).replace(".", "_")


def _directory_hash(path: Path, *, pattern: str = "*.json") -> str:
    if not path.exists():
        return sha256_hex(b"")
    material = b"".join(
        canonical_json_bytes(
            {
                "path": str(item.relative_to(path)),
                "sha256": sha256_hex(item.read_bytes()),
            }
        )
        for item in sorted(path.rglob(pattern))
        if item.is_file()
        and (
            pattern != "rp_*.json"
            or _eligible_report_path(item, path)
        )
    )
    return sha256_hex(material)


def _eligible_report_path(path: Path, reports_root: Path) -> bool:
    relative_parts = path.relative_to(reports_root).parts
    generated_artifact_directories = {
        "acceptance",
        "evaluation",
        "improvement",
        "replay",
        "restore-test",
    }
    return (
        not path.name.endswith(".delivery.json")
        and generated_artifact_directories.isdisjoint(relative_parts)
    )


def _replace_daily_threshold(content: bytes, value: float) -> bytes:
    text = content.decode("utf-8")
    rendered = str(int(value)) if value.is_integer() else str(value)
    pattern = re.compile(r"(?m)^(\s{2}daily:\s*)([0-9]+(?:\.[0-9]+)?)(\s*)$")
    updated, count = pattern.subn(rf"\g<1>{rendered}\g<3>", text)
    if count != 1:
        raise ValueError("scoring policy does not contain one replaceable daily threshold")
    return updated.encode("utf-8")


def _atomic_write(path: Path, content: bytes) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except Exception:
        with suppress(FileNotFoundError):
            os.unlink(temporary_name)
        raise


def _mapping(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise ValueError(f"improvement configuration omitted {key}")
    return item


def _json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def _write_immutable(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError(f"immutable output mismatch: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(content)
