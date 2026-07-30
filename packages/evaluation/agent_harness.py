from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from packages.agents.planning import build_shadow_agent_plans
from packages.agents.runtime import AgentProvider, execute_agent_reviews
from packages.common.canonical import (
    canonical_json_bytes,
    parse_timestamp,
    sha256_hex,
    stable_id,
)
from packages.model_router.router import ModelRouter
from packages.pipeline.frozen import run_frozen_fixture


async def run_agent_evaluation(
    *,
    fixtures_root: Path,
    output_root: Path,
    provider: AgentProvider,
    adapter_name: str,
    repeats: int = 1,
    case: str | None = None,
    models_config: Path = Path("config/models.yaml"),
    maximum_mean_review_duration_ms: int = 300_000,
    maximum_mean_review_tokens: int = 100_000,
) -> dict[str, Any]:
    if not 1 <= repeats <= 10:
        raise ValueError("agent evaluation repeats must be between 1 and 10")
    manifests = tuple(
        sorted(
            fixtures_root.glob(f"{case}-manifest.json" if case is not None else "*-manifest.json")
        )
    )
    if not manifests:
        raise ValueError("agent evaluation found no fixture manifests")
    if maximum_mean_review_duration_ms < 1:
        raise ValueError("maximum mean review duration must be positive")
    if maximum_mean_review_tokens < 1:
        raise ValueError("maximum mean review tokens must be positive")
    cases: list[dict[str, Any]] = []
    assessment_count = 0
    expected_assessment_count = 0
    assessments_with_claims = 0
    claim_count = 0
    cited_claim_count = 0
    coordinator_count = 0
    coordinator_agreement = 0
    role_disposition_counts: dict[str, dict[str, int]] = {}
    role_expected_agreement: dict[str, dict[str, int]] = {}
    failed_roles = 0
    total_duration_ms = 0
    total_input_tokens = 0
    total_output_tokens = 0
    total_estimated_currency = 0.0
    signatures: dict[str, list[str]] = {}

    with TemporaryDirectory(prefix="threat-radar-agent-eval-") as temporary:
        baseline_root = Path(temporary)
        for manifest in manifests:
            baseline = run_frozen_fixture(
                manifest,
                baseline_root / manifest.stem,
            )
            baseline_finding = baseline.report["findings"][0]
            generated_at = parse_timestamp(str(baseline.report["generated_at"]))
            for repeat in range(repeats):
                finding = deepcopy(baseline_finding)
                run_id = stable_id(
                    "run",
                    str(baseline.evidence_packet["packet_id"]),
                    str(repeat),
                )
                plans = build_shadow_agent_plans(
                    [finding],
                    run_id=run_id,
                    generated_at=generated_at,
                    router=ModelRouter.from_path(models_config),
                )
                execution = await execute_agent_reviews(
                    findings=[finding],
                    plans=plans,
                    run_id=run_id,
                    generated_at=generated_at,
                    provider=provider,
                    mode="shadow",
                    packets_by_finding={
                        str(finding["finding_id"]): baseline.evidence_packet,
                    },
                )
                review = execution.reviews[0]
                expected_assessment_count += 5
                assessment_count += len(review["assessments"])
                failed_roles += len(review["failures"])
                total_duration_ms += int(review["duration_ms"])
                review_input_tokens = sum(int(item["input_tokens"]) for item in execution.usage)
                review_output_tokens = sum(int(item["output_tokens"]) for item in execution.usage)
                review_total_tokens = review_input_tokens + review_output_tokens
                total_input_tokens += review_input_tokens
                total_output_tokens += review_output_tokens
                total_estimated_currency += sum(
                    float(item["estimated_currency"]) for item in execution.usage
                )
                for assessment in review["assessments"]:
                    claims = assessment["claims"]
                    assessments_with_claims += bool(claims)
                    claim_count += len(claims)
                    cited_claim_count += sum(bool(claim["evidence_ids"]) for claim in claims)
                    role = str(assessment["agent_role"])
                    disposition = str(assessment["recommended_disposition"])
                    role_disposition_counts.setdefault(role, {})
                    role_disposition_counts[role][disposition] = (
                        role_disposition_counts[role].get(disposition, 0) + 1
                    )
                    role_expected_agreement.setdefault(
                        role,
                        {"agreements": 0, "assessments": 0},
                    )
                    role_expected_agreement[role]["assessments"] += 1
                    role_expected_agreement[role]["agreements"] += (
                        disposition == finding["publication_class"]
                    )
                coordinator = next(
                    (
                        item
                        for item in review["assessments"]
                        if item["agent_role"] == "coordinator"
                    ),
                    None,
                )
                if coordinator is not None:
                    coordinator_count += 1
                    coordinator_agreement += (
                        coordinator["recommended_disposition"]
                        == finding["publication_class"]
                    )
                signature = sha256_hex(
                    canonical_json_bytes(
                        [
                            {
                                key: value
                                for key, value in item.items()
                                if key not in {"assessment_id", "created_at"}
                            }
                            for item in review["assessments"]
                        ]
                    )
                )
                signatures.setdefault(manifest.stem, []).append(signature)
                artifact = {
                    "schema_version": "1.0",
                    "suite": "bounded-agent-evaluation-review",
                    "case": manifest.stem,
                    "repeat": repeat + 1,
                    "adapter": adapter_name,
                    "finding_id": finding["finding_id"],
                    "run_id": run_id,
                    "expected_disposition": finding["publication_class"],
                    "review": review,
                    "usage": list(execution.usage),
                }
                artifact_path = (
                    output_root / "reviews" / f"{manifest.stem}-repeat-{repeat + 1}.json"
                )
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                artifact_bytes = canonical_json_bytes(artifact) + b"\n"
                artifact_path.write_bytes(artifact_bytes)
                cases.append(
                    {
                        "case": manifest.stem,
                        "repeat": repeat + 1,
                        "expected_disposition": finding["publication_class"],
                        "status": review["status"],
                        "completed_roles": [
                            item["agent_role"] for item in review["assessments"]
                        ],
                        "role_dispositions": {
                            str(item["agent_role"]): str(
                                item["recommended_disposition"]
                            )
                            for item in review["assessments"]
                        },
                        "failed_roles": review["failures"],
                        "coordinator_disposition": (
                            coordinator["recommended_disposition"]
                            if coordinator is not None
                            else None
                        ),
                        "duration_ms": review["duration_ms"],
                        "input_tokens": review_input_tokens,
                        "output_tokens": review_output_tokens,
                        "total_tokens": review_total_tokens,
                        "publication_authority": review["publication_authority"],
                        "estimated_currency": round(
                            sum(
                                float(item["estimated_currency"])
                                for item in execution.usage
                            ),
                            6,
                        ),
                        "signature": signature,
                        "assessment_artifact": str(
                            artifact_path.relative_to(output_root)
                        ),
                        "assessment_artifact_sha256": sha256_hex(artifact_bytes),
                    }
                )

    role_completion = (
        assessment_count / expected_assessment_count if expected_assessment_count else 0.0
    )
    claim_coverage = assessments_with_claims / assessment_count if assessment_count else 0.0
    factual_claim_citation_coverage = cited_claim_count / claim_count if claim_count else 0.0
    disposition_agreement = coordinator_agreement / coordinator_count if coordinator_count else 0.0
    reproducible = all(len(set(items)) == 1 for items in signatures.values())
    mean_review_duration_ms = total_duration_ms / len(cases)
    total_tokens = total_input_tokens + total_output_tokens
    mean_review_tokens = total_tokens / len(cases)
    metrics = {
        "case_count": len(manifests),
        "repeat_count": repeats,
        "expected_assessment_count": expected_assessment_count,
        "assessment_count": assessment_count,
        "failed_role_count": failed_roles,
        "role_completion_rate": round(role_completion, 4),
        "assessment_claim_coverage": round(claim_coverage, 4),
        "factual_claim_count": claim_count,
        "cited_factual_claim_count": cited_claim_count,
        "factual_claim_citation_coverage": round(factual_claim_citation_coverage, 4),
        "coordinator_disposition_agreement": round(disposition_agreement, 4),
        "disposition_agreement_by_role": {
            role: round(values["agreements"] / values["assessments"], 4)
            for role, values in sorted(role_expected_agreement.items())
        },
        "dispositions_by_role": {
            role: dict(sorted(counts.items()))
            for role, counts in sorted(role_disposition_counts.items())
        },
        "total_duration_ms": total_duration_ms,
        "mean_review_duration_ms": round(mean_review_duration_ms, 2),
        "input_tokens": total_input_tokens,
        "output_tokens": total_output_tokens,
        "total_tokens": total_tokens,
        "mean_review_tokens": round(mean_review_tokens, 2),
        "estimated_currency": round(total_estimated_currency, 6),
        "repeat_reproducible": reproducible,
    }
    gates = {
        "all_roles_completed": role_completion == 1.0,
        "all_assessments_include_claims": claim_coverage == 1.0,
        "all_factual_claims_cite_evidence": (
            claim_count > 0 and factual_claim_citation_coverage == 1.0
        ),
        "coordinator_agreement_gte_80_percent": disposition_agreement >= 0.8,
        "no_publication_authority": all(case["publication_authority"] is False for case in cases),
        "fixture_repeat_reproducible": (reproducible if adapter_name == "fixture" else True),
        "mean_review_duration_within_limit": (
            mean_review_duration_ms <= maximum_mean_review_duration_ms
        ),
        "mean_review_tokens_within_limit": (mean_review_tokens <= maximum_mean_review_tokens),
    }
    result = {
        "schema_version": "1.0",
        "suite": "bounded-agent-evaluation",
        "adapter": adapter_name,
        "thresholds": {
            "maximum_mean_review_duration_ms": maximum_mean_review_duration_ms,
            "maximum_mean_review_tokens": maximum_mean_review_tokens,
        },
        "metrics": metrics,
        "gates": gates,
        "passed": all(gates.values()),
        "cases": cases,
    }
    output_root.mkdir(parents=True, exist_ok=True)
    (output_root / "agent-eval-results.json").write_bytes(canonical_json_bytes(result) + b"\n")
    return result
