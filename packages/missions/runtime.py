from __future__ import annotations

import asyncio
import copy
import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from packages.agents.planning import build_shadow_agent_plans
from packages.agents.runtime import AgentProvider, execute_agent_reviews
from packages.common.canonical import format_timestamp, parse_timestamp, stable_id
from packages.connectors.base import safe_source_text
from packages.contracts.validation import validate_payload
from packages.discovery.clients import BraveSearchClient, DiscoverySignal
from packages.missions.collectors import MissionCollectorRegistry
from packages.missions.compiler import CompiledMission, MissionDefinition, compile_mission
from packages.missions.renderer import dump_report, render_mission_report, report_json_hash
from packages.model_router.router import ModelRouter

TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9+#.-]{2,}")
TOKEN_STOP_WORDS = {
    "about",
    "after",
    "also",
    "and",
    "are",
    "for",
    "from",
    "into",
    "new",
    "that",
    "the",
    "their",
    "this",
    "with",
}
ACTION_TERMS = {
    "adopt",
    "automation",
    "build",
    "demand",
    "deprecated",
    "friction",
    "launch",
    "migration",
    "need",
    "opportunity",
    "pain",
    "request",
    "replace",
    "ship",
    "workflow",
}
AUTHORITY_BY_TYPE = {
    "authoritative": 100.0,
    "official": 95.0,
    "news": 78.0,
    "github": 72.0,
    "web": 60.0,
    "website": 65.0,
    "rss": 70.0,
    "reddit": 45.0,
    "tiktok": 40.0,
    "x": 40.0,
}


@dataclass(frozen=True, slots=True)
class MissionRunResult:
    report: dict[str, Any]
    report_json_path: Path
    report_html_path: Path
    run_manifest_path: Path
    report_json_hash: str
    rendered_html_hash: str


async def collect_mission_signals(
    compiled: CompiledMission,
    client: BraveSearchClient | None = None,
    *,
    registry: MissionCollectorRegistry | None = None,
) -> dict[str, Any]:
    if not compiled.collection_authorized:
        raise ValueError("live collection requires an approved, active mission")
    if registry is None:
        if client is None:
            raise ValueError(
                "live mission collection requires a collector registry or Brave client"
            )
        registry = MissionCollectorRegistry.with_brave(client)
    surface_by_source = {
        str(source["source_id"]): str(source["surface"])
        for source in compiled.definition.payload["sources"]
    }

    async def collect(query: Any) -> tuple[DiscoverySignal, ...]:
        return await registry.require(str(query.adapter)).collect(query)

    batches = await asyncio.gather(*(collect(query) for query in compiled.queries))
    signals: list[dict[str, Any]] = []
    seen: set[str] = set()
    for batch in batches:
        for signal in batch:
            if signal.url in seen:
                continue
            seen.add(signal.url)
            signals.append(
                {
                    "source_id": signal.source_id,
                    "source_type": signal.source_type
                    or surface_by_source.get(signal.source_id, "web"),
                    "title": signal.title,
                    "url": signal.url,
                    "summary": signal.summary,
                    "published_at": (
                        format_timestamp(signal.published_at) if signal.published_at else None
                    ),
                    "source_handle": signal.source_handle,
                }
            )
    payload = {"schema_version": "1.0", "signals": signals}
    validate_payload("mission-signals.schema.json", payload)
    return payload


async def run_mission(
    mission: MissionDefinition,
    signals_payload: dict[str, Any],
    output_root: Path,
    *,
    generated_at: datetime | None = None,
    agent_mode: str = "plan",
    agent_provider: AgentProvider | None = None,
    model_router: ModelRouter | None = None,
) -> MissionRunResult:
    if agent_mode not in {"plan", "shadow", "active"}:
        raise ValueError("agent mode must be plan, shadow, or active")
    if agent_mode != "plan" and agent_provider is None:
        raise ValueError("shadow and active modes require an agent provider")
    validate_payload("mission-signals.schema.json", signals_payload)
    compiled = compile_mission(mission)
    if generated_at is not None and generated_at.tzinfo is None:
        raise ValueError("generated_at must include a timezone")
    now = (generated_at or datetime.now(UTC)).astimezone(UTC)
    run_id = stable_id("run", mission.mission_id, format_timestamp(now), compiled.mission_sha256)
    allowed_sources = {
        str(source["source_id"]): str(source["surface"])
        for source in mission.payload["sources"]
        if source["enabled"]
    }
    clean_signals = _sanitize_signals(
        signals_payload["signals"],
        now=now,
        allowed_sources=allowed_sources,
        maximum_age_hours=int(mission.payload["evidence"]["maximum_evidence_age_hours"]),
    )
    clusters = _cluster_signals(clean_signals)
    outcomes = _rank_outcomes(compiled, clusters, now=now)
    router = model_router or ModelRouter.from_path(
        Path(__file__).resolve().parents[2] / "config" / "models.yaml"
    )
    synthetic = [_finding_view(item) for item in outcomes]
    plans = build_shadow_agent_plans(
        synthetic,
        run_id=run_id,
        generated_at=now,
        router=router,
    )
    _bind_mission_prompts(plans, mission)
    reviews: list[dict[str, Any]] = []
    usage: list[dict[str, Any]] = []
    if agent_mode != "plan" and synthetic:
        if agent_provider is None:
            raise ValueError("agent provider is required")
        execution = await execute_agent_reviews(
            findings=synthetic,
            plans=plans,
            run_id=run_id,
            generated_at=now,
            provider=agent_provider,
            mode=agent_mode,
            max_concurrency=int(mission.payload["workflow"]["maximum_parallel_roles"]),
        )
        reviews = list(execution.reviews)
        usage = list(execution.usage)
        if agent_mode == "active":
            _copy_review_results(outcomes, synthetic)
    window_hours = int(mission.payload["scope"]["window_hours"])
    report_id = stable_id("mr", run_id, compiled.mission_sha256)
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "report_id": report_id,
        "run_id": run_id,
        "mission_id": mission.mission_id,
        "mission_name": mission.name,
        "objective": mission.objective,
        "generated_at": format_timestamp(now),
        "window": {
            "start": format_timestamp(now - timedelta(hours=window_hours)),
            "end": format_timestamp(now),
            "timezone": "UTC",
        },
        "vocabulary": copy.deepcopy(mission.payload["vocabulary"]),
        "executive_summary": _executive_summary(mission, outcomes),
        "outcomes": outcomes,
        "source_health": _source_health(mission, clean_signals),
        "workflow": {
            "mission_sha256": compiled.mission_sha256,
            "graph": compiled.graph,
            "agent_mode": agent_mode,
            "agent_plans": plans,
            "agent_reviews": reviews,
        },
        "verification": {
            "all_claims_cited": _all_claims_cited(outcomes),
            "minimum_evidence_enforced": True,
            "maximum_evidence_age_enforced": True,
            "code_owned_ranking": True,
        },
        "usage": usage,
    }
    validate_payload("mission-report.schema.json", report)
    run_root = output_root.resolve() / mission.mission_id / report_id
    if run_root.exists():
        raise ValueError(f"refusing to overwrite immutable mission run {run_root}")
    run_root.mkdir(parents=True)
    report_json_path = run_root / "report.json"
    report_html_path = run_root / "report.html"
    run_manifest_path = run_root / "run-manifest.json"
    dump_report(report, report_json_path)
    rendered_hash = render_mission_report(report, report_html_path)
    json_hash = report_json_hash(report)
    manifest = {
        **compiled.to_contract(),
        "run_id": run_id,
        "report_id": report_id,
        "generated_at": format_timestamp(now),
        "input_signal_count": len(clean_signals),
        "qualified_outcome_count": len(outcomes),
        "agent_mode": agent_mode,
        "report_json_sha256": json_hash,
        "report_html_sha256": rendered_hash,
        "external_delivery_executed": False,
    }
    run_manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return MissionRunResult(
        report=report,
        report_json_path=report_json_path,
        report_html_path=report_html_path,
        run_manifest_path=run_manifest_path,
        report_json_hash=json_hash,
        rendered_html_hash=rendered_hash,
    )


def _sanitize_signals(
    values: list[dict[str, Any]],
    *,
    now: datetime,
    allowed_sources: dict[str, str],
    maximum_age_hours: int,
) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        source_id = str(value["source_id"])
        expected_type = allowed_sources.get(source_id)
        if expected_type is None or str(value["source_type"]) != expected_type:
            continue
        title = safe_source_text(value.get("title"), 240)
        summary = safe_source_text(value.get("summary"), 2000)
        url = str(value.get("url") or "")
        parsed = urlsplit(url)
        if title is None or summary is None or parsed.scheme not in {"http", "https"}:
            continue
        if not parsed.hostname or parsed.username or parsed.password or url in seen:
            continue
        published_raw = value.get("published_at")
        published = parse_timestamp(str(published_raw)) if published_raw else None
        if published is not None and published > now + timedelta(minutes=5):
            continue
        if published is not None and now - published > timedelta(hours=maximum_age_hours):
            continue
        seen.add(url)
        sanitized.append(
            {
                "source_id": source_id,
                "source_type": expected_type,
                "title": title,
                "url": url,
                "summary": summary,
                "published_at": format_timestamp(published) if published else None,
                "source_handle": value.get("source_handle"),
                "host": parsed.hostname.lower(),
                "tokens": _tokens(f"{title} {summary}"),
            }
        )
    return sanitized


def _cluster_signals(signals: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    clusters: list[list[dict[str, Any]]] = []
    ordered = sorted(signals, key=lambda item: (str(item["title"]), str(item["url"])))
    for signal in ordered:
        best_index: int | None = None
        best_similarity = 0.0
        for index, cluster in enumerate(clusters):
            comparison_tokens = set().union(*(item["tokens"] for item in cluster))
            similarity = _jaccard(signal["tokens"], comparison_tokens)
            if similarity > best_similarity:
                best_similarity = similarity
                best_index = index
        if best_index is not None and best_similarity >= 0.24:
            clusters[best_index].append(signal)
        else:
            clusters.append([signal])
    return clusters


def _rank_outcomes(
    compiled: CompiledMission,
    clusters: list[list[dict[str, Any]]],
    *,
    now: datetime,
) -> list[dict[str, Any]]:
    mission = compiled.definition
    evidence_floor = int(mission.payload["evidence"]["minimum_independent_sources"])
    outcomes: list[dict[str, Any]] = []
    for cluster in clusters:
        independent = _independence_groups(cluster)
        if len(independent) < evidence_floor:
            continue
        components = _score_components(mission, cluster, now=now)
        dimensions = mission.payload["scoring"]["dimensions"]
        priority_score = round(
            sum(
                components[str(item["dimension_id"])] * float(item["weight"]) / 100
                for item in dimensions
            ),
            2,
        )
        thresholds = mission.payload["scoring"]["thresholds"]
        priority_class = _priority_class(priority_score, thresholds)
        evidence = [_evidence(item, now=now) for item in cluster]
        published = [
            parse_timestamp(str(item["published_at"]))
            for item in cluster
            if item["published_at"] is not None
        ]
        first_observed = min(published) if published else now
        source_types = {str(item["source_type"]) for item in cluster}
        confidence_probability = min(0.96, 0.38 + len(independent) * 0.12 + len(cluster) * 0.04)
        title = _representative_title(cluster)
        cluster_id = stable_id("cl", mission.mission_id, "|".join(sorted(independent)), title)
        outcome_id = stable_id("oc", mission.mission_id, cluster_id)
        claims = [
            {
                "claim_id": stable_id("cm", outcome_id, str(item["evidence_id"])),
                "text": str(item["excerpt"]),
                "certainty": "reported",
                "evidence_ids": [item["evidence_id"]],
                "verification_status": "verified",
            }
            for item in evidence
        ]
        outcomes.append(
            {
                "outcome_id": outcome_id,
                "cluster_id": cluster_id,
                "title": title,
                "why_now": (
                    f"{len(cluster)} recent signals from {len(independent)} independent "
                    f"sources align with the mission objective. The strongest current "
                    f"evidence spans {len(source_types)} source types."
                ),
                "outcome_type": str(mission.payload["vocabulary"]["singular"]),
                "stage": _stage(len(cluster), len(independent)),
                "priority_class": priority_class,
                "priority_score": priority_score,
                "score_components": components,
                "confidence": {
                    "level": (
                        "high"
                        if confidence_probability >= 0.75
                        else "medium"
                        if confidence_probability >= 0.5
                        else "low"
                    ),
                    "probability": round(confidence_probability, 2),
                    "rationale": (
                        f"Based on {len(independent)} independent source hosts and "
                        f"{len(source_types)} source types; no uncited context was added."
                    ),
                },
                "first_observed_at": format_timestamp(first_observed),
                "known": [str(item["excerpt"]) for item in evidence[:5]],
                "unknown": [
                    "Whether the signal will persist beyond the current research window.",
                    "The measurable value for the intended user or organization.",
                ],
                "recommended_actions": [
                    "Review the cited evidence and confirm the outcome fits the stated objective.",
                    "Run a focused follow-up with one authoritative or first-party source.",
                    "Record a useful, not useful, or needs-work decision to calibrate the mission.",
                ],
                "claims": claims,
                "source_evidence": evidence,
                "next_check_at": format_timestamp(now + _cadence_delta(mission)),
            }
        )
    maximum = int(mission.payload["output"]["maximum_outcomes"])
    return sorted(outcomes, key=lambda item: (-float(item["priority_score"]), item["title"]))[
        :maximum
    ]


def _independence_groups(cluster: list[dict[str, Any]]) -> set[str]:
    """Collapse same-site, same-author, and strongly syndicated signals into origins."""
    parent = list(range(len(cluster)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        left_root = find(left)
        right_root = find(right)
        if left_root != right_root:
            parent[max(left_root, right_root)] = min(left_root, right_root)

    for left_index, left in enumerate(cluster):
        for right_index in range(left_index):
            right = cluster[right_index]
            same_site = _site_key(str(left["host"])) == _site_key(str(right["host"]))
            left_handle = str(left.get("source_handle") or "").strip().casefold()
            right_handle = str(right.get("source_handle") or "").strip().casefold()
            same_author = bool(left_handle and left_handle == right_handle)
            left_tokens = set(left["tokens"])
            right_tokens = set(right["tokens"])
            syndicated_copy = (
                min(len(left_tokens), len(right_tokens)) >= 8
                and _jaccard(left_tokens, right_tokens) >= 0.9
            )
            if same_site or same_author or syndicated_copy:
                union(left_index, right_index)

    labels: dict[int, list[str]] = {}
    for index, signal in enumerate(cluster):
        labels.setdefault(find(index), []).append(_site_key(str(signal["host"])))
    return {min(values) for values in labels.values()}


def _site_key(hostname: str) -> str:
    labels = [label for label in hostname.casefold().strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    # This is deliberately conservative: subdomains never count as independent origins.
    return ".".join(labels[-2:])


def _score_components(
    mission: MissionDefinition,
    cluster: list[dict[str, Any]],
    *,
    now: datetime,
) -> dict[str, float]:
    combined_tokens = set().union(*(item["tokens"] for item in cluster))
    objective_tokens = _tokens(
        " ".join([mission.objective, *mission.payload["scope"]["include_terms"]])
    )
    matching = len(combined_tokens & objective_tokens)
    alignment = min(100.0, 25.0 + matching * 12.5)
    hosts = {str(item["host"]) for item in cluster}
    source_types = {str(item["source_type"]) for item in cluster}
    evidence_strength = min(100.0, len(hosts) * 22.0 + len(source_types) * 12.0)
    momentum = min(100.0, 25.0 + math.log2(len(cluster) + 1) * 24.0)
    ages = [
        max(0.0, (now - parse_timestamp(str(item["published_at"]))).total_seconds() / 3600)
        for item in cluster
        if item["published_at"] is not None
    ]
    window = float(mission.payload["scope"]["window_hours"])
    recency = 55.0 if not ages else max(0.0, 100.0 * (1.0 - min(ages) / window))
    actionability = min(100.0, 35.0 + len(combined_tokens & ACTION_TERMS) * 13.0)
    authority = sum(AUTHORITY_BY_TYPE.get(item, 55.0) for item in source_types) / len(
        source_types
    )
    features = {
        "objective_alignment": alignment,
        "evidence_strength": evidence_strength,
        "momentum": momentum,
        "recency": recency,
        "actionability": actionability,
        "source_authority": authority,
    }
    return {
        str(item["dimension_id"]): round(features[str(item["feature"])], 2)
        for item in mission.payload["scoring"]["dimensions"]
    }


def _evidence(signal: dict[str, Any], *, now: datetime) -> dict[str, Any]:
    return {
        "evidence_id": stable_id("ev", str(signal["source_id"]), str(signal["url"])),
        "source_id": signal["source_id"],
        "source_type": signal["source_type"],
        "title": signal["title"],
        "url": signal["url"],
        "published_at": signal["published_at"],
        "retrieved_at": format_timestamp(now),
        "excerpt": signal["summary"],
        "source_handle": signal["source_handle"],
    }


def _finding_view(outcome: dict[str, Any]) -> dict[str, Any]:
    publication = {
        "urgent": "flash",
        "high": "watch",
        "standard": "daily",
        "archive": "archive",
    }[str(outcome["priority_class"])]
    stage = str(outcome["stage"])
    emergence = stage if stage in {"observed", "early_signal", "emerging"} else "observed"
    return {
        "finding_id": outcome["outcome_id"],
        "cluster_id": outcome["cluster_id"],
        "priority_score": outcome["priority_score"],
        "publication_class": publication,
        "confidence": outcome["confidence"],
        "emergence_stage": emergence,
        "source_evidence": copy.deepcopy(outcome["source_evidence"]),
        "claims": copy.deepcopy(outcome["claims"]),
        "unknown": copy.deepcopy(outcome["unknown"]),
    }


def _bind_mission_prompts(plans: list[dict[str, Any]], mission: MissionDefinition) -> None:
    prompts = {
        str(item["role_id"]): str(item["purpose"])
        for item in mission.payload["workflow"]["roles"]
    }
    for plan in plans:
        for route in plan["routes"]:
            route["task_prompt"] = prompts[str(route["role"])]
            route["mission_objective"] = mission.objective
            route["generic_mission"] = True


def _copy_review_results(
    outcomes: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    finding_by_id = {str(item["finding_id"]): item for item in findings}
    for outcome in outcomes:
        finding = finding_by_id[str(outcome["outcome_id"])]
        if finding.get("skeptic_summary"):
            outcome["review_summary"] = str(finding["skeptic_summary"])
        if finding.get("contradictions"):
            outcome["contradictions"] = list(finding["contradictions"])
        outcome["unknown"] = list(finding["unknown"])


def _source_health(
    mission: MissionDefinition,
    signals: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    counts: dict[str, int] = {}
    for signal in signals:
        source_id = str(signal["source_id"])
        counts[source_id] = counts.get(source_id, 0) + 1
    return [
        {
            "source_id": source["source_id"],
            "surface": source["surface"],
            "status": "healthy" if counts.get(str(source["source_id"]), 0) else "no_results",
            "signal_count": counts.get(str(source["source_id"]), 0),
        }
        for source in mission.payload["sources"]
        if source["enabled"]
    ]


def _tokens(value: str) -> set[str]:
    return {
        token
        for token in TOKEN_PATTERN.findall(value.lower())
        if token not in TOKEN_STOP_WORDS
    }


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _representative_title(cluster: list[dict[str, Any]]) -> str:
    return min((str(item["title"]) for item in cluster), key=lambda item: (len(item), item))


def _priority_class(score: float, thresholds: dict[str, Any]) -> str:
    if score >= float(thresholds["urgent"]):
        return "urgent"
    if score >= float(thresholds["high"]):
        return "high"
    if score >= float(thresholds["standard"]):
        return "standard"
    return "archive"


def _stage(signal_count: int, source_count: int) -> str:
    if source_count >= 4 or signal_count >= 6:
        return "emerging"
    if source_count >= 3 or signal_count >= 4:
        return "early_signal"
    return "observed"


def _cadence_delta(mission: MissionDefinition) -> timedelta:
    cadence = str(mission.payload["output"]["cadence"])
    return {
        "hourly": timedelta(hours=1),
        "daily": timedelta(days=1),
        "weekly": timedelta(days=7),
        "manual": timedelta(days=1),
    }[cadence]


def _executive_summary(
    mission: MissionDefinition,
    outcomes: list[dict[str, Any]],
) -> str:
    plural = mission.payload["vocabulary"]["plural"]
    if not outcomes:
        return str(mission.payload["vocabulary"]["empty_result"])
    high = sum(item["priority_class"] in {"urgent", "high"} for item in outcomes)
    return (
        f"The mission found {len(outcomes)} qualified {plural}. "
        f"{high} crossed the high-priority threshold. Every reported claim links to evidence."
    )


def _all_claims_cited(outcomes: list[dict[str, Any]]) -> bool:
    return all(
        bool(claim["evidence_ids"])
        for outcome in outcomes
        for claim in outcome["claims"]
    )
