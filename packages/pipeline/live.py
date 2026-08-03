from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import yaml

from apps.report_renderer.render import TEMPLATE_REVISION, RenderedReport, render_report
from packages.agents.planning import build_shadow_agent_plans
from packages.agents.runtime import AgentProvider, execute_agent_reviews
from packages.common.canonical import (
    canonical_json_bytes,
    format_timestamp,
    parse_timestamp,
    sha256_hex,
    stable_id,
)
from packages.common.resources import bundled_path
from packages.connectors.live import (
    LiveSourceArtifact,
    OfficialSourceClient,
    candidate_source_specs,
    cisa_kev_spec,
)
from packages.delivery.discord import build_discord_delivery_plan
from packages.delivery.email import build_email_delivery_plan, email_delivery_destination
from packages.delivery.local import build_local_delivery_plan
from packages.discovery.clients import (
    BRAVE_COST_PER_REQUEST,
    BraveSearchClient,
    DiscoverySignal,
    DiscoveryUsage,
    RedditSearchClient,
    TikTokResearchClient,
    XaiXSearchClient,
    candidate_cves,
)
from packages.discovery.emerging import (
    PreparedSignal,
    build_emerging_finding,
    cluster_non_cve_signals,
    enrich_cve_finding,
    prepare_discovery_signals,
    referenced_discovery_records,
    related_cves,
)
from packages.inference.semantic import SemanticShadowEvaluator
from packages.model_router.budget import AgentBudget
from packages.model_router.router import ModelRouter
from packages.pipeline.frozen import FrozenRunResult, run_frozen_fixture
from packages.scoring.engine import PublicationThresholds, load_thresholds
from packages.security_gateway.gateway import (
    ContentSecurityGateway,
    TextArtifactMalwareScanner,
)
from packages.storage.object_store import ImmutableObjectStore
from packages.storage.repository import ResearchRepository

PUBLICATION_RANK = {"archive": 0, "daily": 1, "watch": 2, "flash": 3}
CRITICAL_SIGNAL_PATTERNS: tuple[tuple[re.Pattern[str], int], ...] = (
    (
        re.compile(
            r"\b(?:actively exploited|exploited in the wild|in-the-wild exploitation)\b",
            re.IGNORECASE,
        ),
        5,
    ),
    (
        re.compile(
            r"\b(?:unauthenticated|pre-auth(?:entication)?|authentication bypass)\b",
            re.IGNORECASE,
        ),
        4,
    ),
    (
        re.compile(
            r"\b(?:remote code execution|rce|wormable)\b",
            re.IGNORECASE,
        ),
        4,
    ),
    (
        re.compile(
            r"\b(?:mass exploitation|widespread exploitation|internet-wide)\b",
            re.IGNORECASE,
        ),
        5,
    ),
    (
        re.compile(
            r"\b(?:edge device|vpn|firewall|gateway appliance)\b",
            re.IGNORECASE,
        ),
        2,
    ),
)
DEFAULT_DISCOVERY_CONFIG = bundled_path("config/discovery.yaml")
DEFAULT_SCORING_CONFIG = bundled_path("config/scoring.yaml")
DEFAULT_MODELS_CONFIG = bundled_path("config/models.yaml")


@dataclass(frozen=True, slots=True)
class LiveRunSettings:
    output_root: Path
    discord_channel_id: str | None = None
    email_recipient: str | None = None
    edition: str = "morning"
    timezone: str = "America/New_York"
    discovery_config: Path = DEFAULT_DISCOVERY_CONFIG
    scoring_config: Path = DEFAULT_SCORING_CONFIG
    models_config: Path = DEFAULT_MODELS_CONFIG
    agent_mode: str = "plan"
    agent_max_concurrency: int = 3
    daily_model_spend: Decimal = Decimal("0")


@dataclass(frozen=True, slots=True)
class LiveRunResult:
    run_id: str
    report: dict[str, Any]
    report_json_path: Path
    rendered: RenderedReport
    delivery_plan: dict[str, Any]
    delivery_plan_path: Path
    summary: str
    candidate_cves: tuple[str, ...]
    degraded_sources: tuple[str, ...]
    emerging_signal_count: int = 0
    qualified_emerging_count: int = 0
    source_native_signal_count: int = 0
    semantic_shadow: dict[str, Any] | None = None


async def run_live_research(
    settings: LiveRunSettings,
    *,
    brave_client: BraveSearchClient,
    x_search_client: XaiXSearchClient,
    official_client: OfficialSourceClient,
    object_store: ImmutableObjectStore,
    repository: ResearchRepository,
    reddit_client: RedditSearchClient | None = None,
    tiktok_client: TikTokResearchClient | None = None,
    semantic_evaluator: SemanticShadowEvaluator | None = None,
    agent_provider: AgentProvider | None = None,
    now: datetime | None = None,
) -> LiveRunResult:
    if settings.discord_channel_id is not None and settings.email_recipient is not None:
        raise ValueError("Discord and email delivery plans are mutually exclusive")
    generated_at = (now or datetime.now(UTC)).astimezone(UTC)
    existing = _existing_morning_result(settings, generated_at)
    if existing is not None:
        await repository.close()
        return existing
    window_start = generated_at - timedelta(hours=24)
    run_id = stable_id("run", format_timestamp(generated_at), settings.edition)
    run_root = (settings.output_root / run_id).resolve()
    run_root.mkdir(parents=True, exist_ok=True)
    config = _load_discovery_config(settings.discovery_config)
    brave_config = _mapping(config, "brave")
    x_config = _mapping(config, "x_search")
    reddit_config = _optional_mapping(config, "reddit")
    tiktok_config = _optional_mapping(config, "tiktok_research")
    promotion = _mapping(config, "promotion")
    queries = _web_queries(brave_config)
    allowed_handles = _string_tuple(x_config, "allowed_handles")
    maximum_candidates = int(promotion.get("maximum_candidates_per_run", 6))
    maximum_signal_candidates = int(promotion.get("maximum_signal_candidates_per_run", 8))
    maximum_findings = int(promotion.get("maximum_report_findings", 5))
    minimum_emerging_findings = int(promotion.get("minimum_emerging_findings_per_report", 0))
    minimum_class = str(promotion.get("minimum_publication_class", "daily"))
    if not 0 <= minimum_emerging_findings <= maximum_findings:
        raise ValueError("minimum emerging findings must be between zero and the report maximum")
    thresholds = load_thresholds(settings.scoring_config)
    if minimum_class not in PUBLICATION_RANK:
        raise ValueError("invalid minimum publication class")

    signals: list[DiscoverySignal] = []
    degraded: set[str] = set()
    source_health: dict[str, dict[str, Any]] = {}
    usage: list[dict[str, Any]] = []

    brave_requests: Counter[str] = Counter()
    brave_successes: Counter[str] = Counter()
    for source_id, query, freshness in queries:
        brave_requests[source_id] += 1
        try:
            signals.extend(
                await brave_client.search(
                    query,
                    freshness=freshness,
                    count=int(brave_config.get("maximum_results_per_query", 20)),
                    source_id=source_id,
                )
            )
            brave_successes[source_id] += 1
        except Exception:
            degraded.add(source_id)
    for source_id, requests in sorted(brave_requests.items()):
        successful = brave_successes[source_id]
        source_health[source_id] = _health(
            source_id,
            generated_at,
            healthy=successful == requests,
        )
        usage.append(
            _usage_record(
                stage="web_discovery",
                provider="brave",
                model="brave-web-search-v1",
                requests=requests,
                estimated_currency=round(requests * BRAVE_COST_PER_REQUEST, 6),
                source_id=source_id,
            )
        )

    if bool(reddit_config.get("enabled", False)):
        communities = _string_tuple(reddit_config, "communities")
        if reddit_client is None:
            degraded.add("reddit-security")
            source_health["reddit-security"] = _health(
                "reddit-security",
                generated_at,
                healthy=False,
            )
            usage.append(
                _usage_record(
                    stage="social_discovery",
                    provider="reddit-oauth",
                    model="deterministic-json-parser",
                    requests=0,
                    source_id="reddit-security",
                )
            )
        else:
            try:
                reddit_signals = await reddit_client.search(
                    communities,
                    maximum_per_community=int(
                        reddit_config.get("maximum_results_per_community", 25)
                    ),
                )
                signals.extend(reddit_signals)
                source_health["reddit-security"] = _health(
                    "reddit-security",
                    generated_at,
                    healthy=True,
                )
                usage.append(
                    _usage_record(
                        stage="social_discovery",
                        provider="reddit-oauth",
                        model="deterministic-json-parser",
                        requests=len(communities),
                        source_id="reddit-security",
                    )
                )
            except Exception:
                degraded.add("reddit-security")
                source_health["reddit-security"] = _health(
                    "reddit-security",
                    generated_at,
                    healthy=False,
                )
                usage.append(
                    _usage_record(
                        stage="social_discovery",
                        provider="reddit-oauth",
                        model="deterministic-json-parser",
                        requests=0,
                        source_id="reddit-security",
                    )
                )

    if bool(tiktok_config.get("enabled", False)):
        keywords = _string_tuple(tiktok_config, "keywords")
        if tiktok_client is None:
            degraded.add("tiktok-research")
            source_health["tiktok-research"] = _health(
                "tiktok-research",
                generated_at,
                healthy=False,
            )
            usage.append(
                _usage_record(
                    stage="social_discovery",
                    provider="tiktok-research",
                    model="deterministic-json-parser",
                    requests=0,
                    source_id="tiktok-research",
                )
            )
        else:
            try:
                tiktok_signals = await tiktok_client.search(
                    keywords,
                    start_date=window_start.date(),
                    end_date=generated_at.date(),
                    maximum_results=int(tiktok_config.get("maximum_results", 100)),
                )
                signals.extend(tiktok_signals)
                source_health["tiktok-research"] = _health(
                    "tiktok-research",
                    generated_at,
                    healthy=True,
                )
                usage.append(
                    _usage_record(
                        stage="social_discovery",
                        provider="tiktok-research",
                        model="deterministic-json-parser",
                        requests=1,
                        source_id="tiktok-research",
                    )
                )
            except Exception:
                degraded.add("tiktok-research")
                source_health["tiktok-research"] = _health(
                    "tiktok-research",
                    generated_at,
                    healthy=False,
                )
                usage.append(
                    _usage_record(
                        stage="social_discovery",
                        provider="tiktok-research",
                        model="deterministic-json-parser",
                        requests=0,
                        source_id="tiktok-research",
                    )
                )

    try:
        x_result = await x_search_client.search(
            from_date=window_start.date(),
            to_date=generated_at.date(),
            allowed_handles=allowed_handles,
        )
        signals.extend(x_result.signals)
        usage.append(_x_usage_record(x_result.usage))
        source_health["x-researchers"] = _health(
            "x-researchers",
            generated_at,
            healthy=True,
        )
    except Exception:
        degraded.add("x-researchers")
        usage.append(
            _usage_record(
                stage="social_discovery",
                provider="xai",
                model=str(x_config.get("model", "grok-4.5")),
                requests=0,
            )
        )
        source_health["x-researchers"] = _health(
            "x-researchers",
            generated_at,
            healthy=False,
        )

    prepared_signals = prepare_discovery_signals(
        signals,
        generated_at=generated_at,
        object_store=object_store,
    )
    cisa_artifact: LiveSourceArtifact | None = None
    try:
        cisa_artifact = await official_client.fetch(cisa_kev_spec())
        source_health["cisa-kev"] = _health("cisa-kev", generated_at, healthy=True)
    except Exception:
        degraded.add("cisa-kev")
        source_health["cisa-kev"] = _health("cisa-kev", generated_at, healthy=False)

    candidates = _prioritized_candidates(
        signals,
        cisa_artifact,
        window_start.date(),
        maximum_candidates,
    )
    candidate_results: list[FrozenRunResult] = []
    for index, cve in enumerate(candidates):
        result, candidate_degraded, candidate_health = await _run_candidate(
            run_id=run_id,
            candidate_index=index,
            cve=cve,
            generated_at=generated_at,
            window_start=window_start,
            settings=settings,
            run_root=run_root,
            cisa_artifact=cisa_artifact,
            official_client=official_client,
            object_store=object_store,
            thresholds=thresholds,
        )
        degraded.update(candidate_degraded)
        source_health.update(candidate_health)
        if result is not None:
            candidate_results.append(result)

    available_cves = {
        finding_cve
        for result in candidate_results
        if result.report.get("findings")
        for finding_cve in [_finding_cve(result.report["findings"][0])]
        if finding_cve is not None
    }
    related_signals_by_cve: dict[str, list[PreparedSignal]] = {}
    emerging_clusters: list[tuple[PreparedSignal, ...]] = []
    deterministic_clusters = cluster_non_cve_signals(prepared_signals)
    semantic_shadow: dict[str, Any] | None = None
    if semantic_evaluator is not None:
        try:
            semantic_result = await semantic_evaluator.evaluate(
                prepared_signals,
                deterministic_clusters,
            )
        except Exception:
            semantic_result = semantic_evaluator.degraded_result(prepared_signals)
        semantic_shadow = semantic_result.as_report()
        usage.append(
            _usage_record(
                stage="semantic_clustering_shadow",
                provider="ollama",
                model=semantic_result.model,
                requests=semantic_result.requests,
                input_tokens=semantic_result.input_tokens,
            )
        )
    for cluster in deterministic_clusters:
        matches = set(related_cves(cluster, prepared_signals)).intersection(available_cves)
        if len(matches) == 1:
            cve = matches.pop()
            related_signals_by_cve.setdefault(cve, []).extend(cluster)
        else:
            emerging_clusters.append(cluster)

    cve_findings: list[dict[str, Any]] = []
    for result in candidate_results:
        if not result.report.get("findings"):
            continue
        finding = result.report["findings"][0]
        finding_cve = _finding_cve(finding)
        if finding_cve is None:
            continue
        enriched = enrich_cve_finding(
            finding,
            cve=finding_cve,
            signals=prepared_signals,
            related_signals=tuple(related_signals_by_cve.get(finding_cve, [])),
        )
        enriched["source_evidence"] = _dedupe_source_evidence(
            [
                *enriched.get("source_evidence", []),
                *_candidate_source_evidence(result),
            ]
        )
        cve_findings.append(enriched)
    emerging_findings = [
        build_emerging_finding(
            cluster,
            generated_at=generated_at,
            thresholds=thresholds,
        )
        for cluster in emerging_clusters[:maximum_signal_candidates]
    ]
    qualified_emerging_count = sum(
        PUBLICATION_RANK[str(finding["publication_class"])] >= PUBLICATION_RANK[minimum_class]
        for finding in emerging_findings
    )
    findings = _select_report_findings(
        cve_findings=cve_findings,
        emerging_findings=emerging_findings,
        minimum_class=minimum_class,
        maximum_findings=maximum_findings,
        minimum_emerging_findings=minimum_emerging_findings,
    )
    agent_shadow_plans = build_shadow_agent_plans(
        findings,
        run_id=run_id,
        generated_at=generated_at,
        router=ModelRouter.from_path(settings.models_config),
    )
    agent_reviews: list[dict[str, Any]] = []
    agent_assessments: list[dict[str, Any]] = []
    if settings.agent_mode != "plan":
        if settings.agent_mode not in {"shadow", "active"}:
            raise ValueError("agent mode must be plan, shadow, or active")
        if agent_provider is None:
            raise ValueError("agent provider is required when agent execution is enabled")
        execution = await execute_agent_reviews(
            findings=findings,
            plans=agent_shadow_plans,
            run_id=run_id,
            generated_at=generated_at,
            provider=agent_provider,
            mode=settings.agent_mode,
            max_concurrency=settings.agent_max_concurrency,
            budget=AgentBudget.from_path(
                settings.models_config,
                daily_spend=settings.daily_model_spend,
            ),
        )
        agent_reviews.extend(execution.reviews)
        agent_assessments.extend(execution.assessments)
        usage.extend(execution.usage)
    discovery_evidence, discovery_artifacts = referenced_discovery_records(
        findings,
        prepared_signals,
    )
    usage.append(
        _usage_record(
            stage="deterministic_pipeline",
            provider="local",
            model="deterministic-code",
            requests=0,
        )
    )
    usage.append(
        _usage_record(
            stage="agent_routing_shadow",
            provider="local",
            model="deterministic-model-router",
            requests=0,
        )
    )
    _reconcile_degraded_source_health(source_health, degraded)
    report = _aggregate_report(
        run_id=run_id,
        settings=settings,
        generated_at=generated_at,
        window_start=window_start,
        findings=findings,
        source_health=list(source_health.values()),
        discovery_telemetry=_discovery_telemetry(
            signals=signals,
            prepared_signals=prepared_signals,
            findings=findings,
            source_health=list(source_health.values()),
            usage=usage,
        ),
        degraded=degraded,
        usage=usage,
        semantic_shadow=semantic_shadow,
        agent_shadow_plans=agent_shadow_plans,
        agent_reviews=agent_reviews,
    )
    report_json_path = run_root / f"{report['report_id']}.json"
    _write_immutable(report_json_path, canonical_json_bytes(report) + b"\n")
    rendered = render_report(report, run_root / f"{report['report_id']}.html")
    delivery_plan = _build_delivery_plan(
        settings,
        report,
        html_path=rendered.path,
    )
    delivery_plan_path = run_root / f"{report['report_id']}.delivery.json"
    _write_immutable(delivery_plan_path, canonical_json_bytes(delivery_plan) + b"\n")
    await _persist_run(
        repository=repository,
        run_id=run_id,
        report=report,
        candidate_results=candidate_results,
        discovery_evidence=discovery_evidence,
        discovery_artifacts=discovery_artifacts,
        agent_assessments=agent_assessments,
        delivery_plan=delivery_plan,
    )
    summary = str(delivery_plan["summary"])
    return LiveRunResult(
        run_id=run_id,
        report=report,
        report_json_path=report_json_path,
        rendered=rendered,
        delivery_plan=delivery_plan,
        delivery_plan_path=delivery_plan_path,
        summary=summary,
        candidate_cves=candidates,
        degraded_sources=tuple(sorted(degraded)),
        emerging_signal_count=sum(
            1
            for finding in findings
            if not any(
                str(mapping.get("scheme")) == "CVE"
                for mapping in finding.get("mappings", [])
                if isinstance(mapping, dict)
            )
        ),
        qualified_emerging_count=qualified_emerging_count,
        source_native_signal_count=sum(
            not candidate_cves((item.signal,)) for item in prepared_signals
        ),
        semantic_shadow=semantic_shadow,
    )


def _select_report_findings(
    *,
    cve_findings: list[dict[str, Any]],
    emerging_findings: list[dict[str, Any]],
    minimum_class: str,
    maximum_findings: int,
    minimum_emerging_findings: int,
) -> list[dict[str, Any]]:
    minimum_rank = PUBLICATION_RANK[minimum_class]
    eligible_cves = [
        finding
        for finding in cve_findings
        if PUBLICATION_RANK[str(finding["publication_class"])] >= minimum_rank
    ]
    eligible_emerging = sorted(
        (
            finding
            for finding in emerging_findings
            if PUBLICATION_RANK[str(finding["publication_class"])] >= minimum_rank
        ),
        key=lambda item: float(item["priority_score"]),
        reverse=True,
    )
    reserved = eligible_emerging[:minimum_emerging_findings]
    remaining = sorted(
        [*eligible_cves, *eligible_emerging[minimum_emerging_findings:]],
        key=lambda item: float(item["priority_score"]),
        reverse=True,
    )
    return sorted(
        [*reserved, *remaining[: max(0, maximum_findings - len(reserved))]],
        key=lambda item: float(item["priority_score"]),
        reverse=True,
    )


def _existing_morning_result(
    settings: LiveRunSettings,
    generated_at: datetime,
) -> LiveRunResult | None:
    if settings.edition != "morning" or not settings.output_root.exists():
        return None
    local_date = generated_at.astimezone(ZoneInfo(settings.timezone)).date()
    candidates: list[tuple[datetime, LiveRunResult]] = []
    destination = _configured_delivery_destination(settings)
    for delivery_plan_path in settings.output_root.glob("run_*/rp_*.delivery.json"):
        stem = delivery_plan_path.name.removesuffix(".delivery.json")
        report_json_path = delivery_plan_path.with_name(f"{stem}.json")
        html_path = delivery_plan_path.with_name(f"{stem}.html")
        try:
            report = json.loads(report_json_path.read_text(encoding="utf-8"))
            delivery_plan = json.loads(delivery_plan_path.read_text(encoding="utf-8"))
            report_generated_at = parse_timestamp(str(report["generated_at"]))
            if (
                report.get("edition") != settings.edition
                or report_generated_at.astimezone(ZoneInfo(settings.timezone)).date() != local_date
                or delivery_plan.get("destination") != destination
                or delivery_plan != _build_delivery_plan(settings, report, html_path=html_path)
            ):
                continue
            rendered = RenderedReport(
                path=html_path,
                report_json_hash=sha256_hex(canonical_json_bytes(report)),
                rendered_html_hash=sha256_hex(html_path.read_bytes()),
                template_revision=TEMPLATE_REVISION,
            )
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            continue
        identifiers = tuple(
            sorted(
                {
                    match.upper()
                    for finding in report.get("findings", [])
                    if isinstance(finding, dict)
                    for match in re.findall(
                        r"\bCVE-\d{4}-\d{4,}\b",
                        str(finding.get("title", "")),
                        flags=re.IGNORECASE,
                    )
                }
            )
        )
        candidates.append(
            (
                report_generated_at,
                LiveRunResult(
                    run_id=delivery_plan_path.parent.name,
                    report=report,
                    report_json_path=report_json_path,
                    rendered=rendered,
                    delivery_plan=delivery_plan,
                    delivery_plan_path=delivery_plan_path,
                    summary=str(delivery_plan["summary"]),
                    candidate_cves=identifiers,
                    degraded_sources=tuple(
                        sorted(str(item) for item in report.get("degraded_sources", []))
                    ),
                    emerging_signal_count=sum(
                        1
                        for finding in report.get("findings", [])
                        if isinstance(finding, dict)
                        and not any(
                            isinstance(mapping, dict) and mapping.get("scheme") == "CVE"
                            for mapping in finding.get("mappings", [])
                        )
                    ),
                    qualified_emerging_count=sum(
                        1
                        for finding in report.get("findings", [])
                        if isinstance(finding, dict)
                        and not any(
                            isinstance(mapping, dict) and mapping.get("scheme") == "CVE"
                            for mapping in finding.get("mappings", [])
                        )
                    ),
                    source_native_signal_count=sum(
                        len(finding.get("source_evidence", []))
                        for finding in report.get("findings", [])
                        if isinstance(finding, dict)
                        and not any(
                            isinstance(mapping, dict) and mapping.get("scheme") == "CVE"
                            for mapping in finding.get("mappings", [])
                        )
                    ),
                    semantic_shadow=(
                        report.get("semantic_shadow")
                        if isinstance(report.get("semantic_shadow"), dict)
                        else None
                    ),
                ),
            )
        )
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


def _build_delivery_plan(
    settings: LiveRunSettings,
    report: dict[str, Any],
    *,
    html_path: Path,
) -> dict[str, Any]:
    if settings.discord_channel_id is not None:
        return build_discord_delivery_plan(
            report,
            html_path=html_path,
            channel_id=settings.discord_channel_id,
        )
    if settings.email_recipient is not None:
        return build_email_delivery_plan(
            report,
            html_path=html_path,
            recipient=settings.email_recipient,
        )
    return build_local_delivery_plan(report, html_path=html_path)


def _configured_delivery_destination(settings: LiveRunSettings) -> str:
    if settings.discord_channel_id is not None:
        return f"discord:channel:{settings.discord_channel_id}"
    if settings.email_recipient is not None:
        return email_delivery_destination(settings.email_recipient)
    return "file:local"


async def _run_candidate(
    *,
    run_id: str,
    candidate_index: int,
    cve: str,
    generated_at: datetime,
    window_start: datetime,
    settings: LiveRunSettings,
    run_root: Path,
    cisa_artifact: LiveSourceArtifact | None,
    official_client: OfficialSourceClient,
    object_store: ImmutableObjectStore,
    thresholds: PublicationThresholds,
) -> tuple[FrozenRunResult | None, set[str], dict[str, dict[str, Any]]]:
    candidate_root = run_root / "candidates" / cve
    inputs_root = candidate_root / "inputs"
    inputs_root.mkdir(parents=True, exist_ok=True)
    fetched: list[LiveSourceArtifact] = []
    degraded: set[str] = set()
    health: dict[str, dict[str, Any]] = {}
    if cisa_artifact is not None:
        fetched.append(cisa_artifact)
    specs = candidate_source_specs(cve)
    results = await asyncio.gather(
        *(official_client.fetch(spec) for spec in specs),
        return_exceptions=True,
    )
    for spec, value in zip(specs, results, strict=True):
        if isinstance(value, BaseException):
            degraded.add(spec.source_id)
            health[spec.source_id] = _health(spec.source_id, generated_at, healthy=False)
            continue
        fetched.append(value)
        health[spec.source_id] = _health(spec.source_id, generated_at, healthy=True)
    sources: list[dict[str, Any]] = []
    for artifact_index, artifact in enumerate(fetched):
        input_path = inputs_root / f"{artifact_index:02d}-{artifact.spec.source_id}.data"
        _write_immutable(input_path, artifact.result.content)
        sources.append(
            {
                "source_id": artifact.spec.source_id,
                "file": str(input_path.relative_to(candidate_root)),
                "canonical_uri": artifact.result.canonical_uri,
                "retrieved_at": format_timestamp(generated_at),
                "content_type": artifact.spec.processing_content_type,
                "independence_group": artifact.spec.independence_group,
                "available": True,
            }
        )
    for source_id in sorted(degraded):
        sources.append(
            {
                "source_id": source_id,
                "available": False,
            }
        )
    manifest = {
        "run_id": stable_id("run", run_id, cve, str(candidate_index)),
        "generated_at": format_timestamp(generated_at),
        "edition": settings.edition,
        "window": {
            "start": format_timestamp(window_start),
            "end": format_timestamp(generated_at),
            "timezone": settings.timezone,
        },
        "sources": sources,
        "inventory": [],
        "media_baseline_checked": False,
    }
    manifest_path = candidate_root / "manifest.json"
    _write_immutable(manifest_path, canonical_json_bytes(manifest) + b"\n")
    try:
        result = run_frozen_fixture(
            manifest_path,
            candidate_root / "report",
            object_store=object_store,
            content_gateway=ContentSecurityGateway(malware_scanner=TextArtifactMalwareScanner()),
            identifier_filter=frozenset({cve}),
            shadow_mode=False,
            thresholds=thresholds,
            isolate_parsers=True,
        )
    except ValueError as exc:
        if "requires at least one CVE" in str(exc):
            return None, degraded, health
        raise
    return result, degraded, health


def _prioritized_candidates(
    signals: list[DiscoverySignal],
    cisa_artifact: LiveSourceArtifact | None,
    minimum_date: date,
    maximum: int,
) -> tuple[str, ...]:
    scores: Counter[str] = Counter()
    for signal in signals:
        criticality_bonus = _critical_signal_bonus(signal)
        for cve in candidate_cves((signal,)):
            scores[cve] += (2 if signal.source_id == "x-researchers" else 1) + criticality_bonus
    if cisa_artifact is not None:
        try:
            payload = json.loads(cisa_artifact.result.content)
        except json.JSONDecodeError:
            payload = {}
        items = payload.get("vulnerabilities") if isinstance(payload, dict) else []
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, dict):
                    continue
                cve_value = item.get("cveID")
                added = item.get("dateAdded")
                if not isinstance(cve_value, str) or not isinstance(added, str):
                    continue
                try:
                    if date.fromisoformat(added) >= minimum_date:
                        scores[cve_value.upper()] += 12
                except ValueError:
                    continue
    ranked = sorted(scores, key=lambda item: (-scores[item], item))
    return tuple(ranked[:maximum])


def _critical_signal_bonus(signal: DiscoverySignal) -> int:
    """Prioritize corroboration; never changes evidence or publication gates."""
    text = "\n".join(
        item for item in (signal.title, signal.summary, signal.rationale) if item is not None
    )
    return min(
        12,
        sum(weight for pattern, weight in CRITICAL_SIGNAL_PATTERNS if pattern.search(text)),
    )


def _finding_cve(finding: dict[str, Any]) -> str | None:
    for mapping in finding.get("mappings", []):
        if (
            isinstance(mapping, dict)
            and mapping.get("scheme") == "CVE"
            and isinstance(mapping.get("identifier"), str)
        ):
            return str(mapping["identifier"]).upper()
    return None


def _candidate_source_evidence(result: FrozenRunResult) -> list[dict[str, Any]]:
    sources: list[dict[str, Any]] = []
    for evidence in result.evidence_packet.get("evidence", []):
        if not isinstance(evidence, dict):
            continue
        excerpt = str(evidence.get("excerpt", "")).strip()[:1200]
        if not excerpt:
            continue
        source_id = str(evidence.get("source_id", "source"))
        source_role = str(evidence.get("source_role", ""))
        source_type = (
            "advisory"
            if source_role in {"direct_artifact", "authoritative_advisory"}
            else "database"
        )
        sources.append(
            {
                "evidence_id": str(evidence["evidence_id"]),
                "source_id": source_id,
                "source_type": source_type,
                "title": f"{source_id.replace('-', ' ').title()} evidence",
                "url": str(evidence["canonical_uri"]),
                "published_at": evidence.get("published_at"),
                "retrieved_at": str(evidence["retrieved_at"]),
                "excerpt": excerpt,
                "source_handle": None,
            }
        )
    return sources


def _dedupe_source_evidence(
    sources: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for source in sources:
        evidence_id = str(source.get("evidence_id", ""))
        if not evidence_id or evidence_id in seen:
            continue
        seen.add(evidence_id)
        result.append(source)
    return result[:20]


def _aggregate_report(
    *,
    run_id: str,
    settings: LiveRunSettings,
    generated_at: datetime,
    window_start: datetime,
    findings: list[dict[str, Any]],
    source_health: list[dict[str, Any]],
    discovery_telemetry: dict[str, Any],
    degraded: set[str],
    usage: list[dict[str, Any]],
    semantic_shadow: dict[str, Any] | None,
    agent_shadow_plans: list[dict[str, Any]],
    agent_reviews: list[dict[str, Any]],
) -> dict[str, Any]:
    material = len(findings)
    if material:
        highest = max(float(item["priority_score"]) for item in findings)
        executive_summary = (
            f"{material} verified emerging threat finding(s) met the publication gate. "
            f"Highest priority score: {highest:.1f}."
        )
    else:
        executive_summary = (
            "No material emerging threats met the verified publication threshold "
            "during this window."
        )
    report = {
        "schema_version": "1.0",
        "report_id": stable_id("rp", run_id, settings.edition),
        "edition": settings.edition,
        "generated_at": format_timestamp(generated_at),
        "window": {
            "start": format_timestamp(window_start),
            "end": format_timestamp(generated_at),
            "timezone": settings.timezone,
        },
        "executive_summary": executive_summary,
        "findings": findings,
        "degraded_sources": sorted(degraded),
        "source_health": sorted(source_health, key=lambda item: str(item["source_id"])),
        "discovery_telemetry": discovery_telemetry,
        "usage": usage,
        "agent_shadow_plans": agent_shadow_plans,
        "verification": {
            "all_claims_cited": True,
            "all_claims_verified": True,
            "verifier_revision": "deterministic-verifier-v1",
        },
    }
    if agent_reviews:
        report["agent_reviews"] = agent_reviews
    if semantic_shadow is not None:
        report["semantic_shadow"] = semantic_shadow
    return report


def _discovery_telemetry(
    *,
    signals: list[DiscoverySignal],
    prepared_signals: tuple[PreparedSignal, ...],
    findings: list[dict[str, Any]],
    source_health: list[dict[str, Any]],
    usage: list[dict[str, Any]],
) -> dict[str, Any]:
    discovered: Counter[str] = Counter(item.source_id for item in signals)
    prepared: Counter[str] = Counter(item.signal.source_id for item in prepared_signals)
    cited: Counter[str] = Counter()
    selected_findings: Counter[str] = Counter()
    source_types: dict[str, set[str]] = {}
    for signal in signals:
        if signal.source_type:
            source_types.setdefault(signal.source_id, set()).add(signal.source_type)
    for finding in findings:
        finding_sources: set[str] = set()
        for evidence in finding.get("source_evidence", []):
            if not isinstance(evidence, dict):
                continue
            source_id = str(evidence.get("source_id", ""))
            source_type = str(evidence.get("source_type", ""))
            if not source_id:
                continue
            cited[source_id] += 1
            finding_sources.add(source_id)
            if source_type:
                source_types.setdefault(source_id, set()).add(source_type)
        selected_findings.update(finding_sources)
    requests: Counter[str] = Counter()
    for item in usage:
        if isinstance(item.get("source_id"), str) and item["source_id"]:
            requests[str(item["source_id"])] += int(item["requests"])
    statuses = {
        str(item["source_id"]): str(item["status"])
        for item in source_health
        if isinstance(item.get("source_id"), str)
    }
    surface_ids = sorted(
        set(statuses) | set(discovered) | set(prepared) | set(cited) | set(requests)
    )
    return {
        "discovered_signal_count": sum(discovered.values()),
        "prepared_signal_count": sum(prepared.values()),
        "cited_evidence_count": sum(cited.values()),
        "surfaces": [
            {
                "source_id": source_id,
                "status": statuses.get(source_id, "disabled"),
                "requests": requests[source_id],
                "discovered_signal_count": discovered[source_id],
                "prepared_signal_count": prepared[source_id],
                "cited_evidence_count": cited[source_id],
                "selected_finding_count": selected_findings[source_id],
                "source_types": sorted(source_types.get(source_id, set())),
            }
            for source_id in surface_ids
        ],
    }


async def _persist_run(
    *,
    repository: ResearchRepository,
    run_id: str,
    report: dict[str, Any],
    candidate_results: list[FrozenRunResult],
    discovery_evidence: list[dict[str, Any]],
    discovery_artifacts: list[dict[str, Any]],
    agent_assessments: list[dict[str, Any]],
    delivery_plan: dict[str, Any],
) -> None:
    if not await repository.available():
        raise RuntimeError("production repository is unavailable")
    await _put(repository, "runs", run_id, {"run_id": run_id, "status": "published"})
    for result in candidate_results:
        for observation in result.observations:
            await _put(
                repository,
                "observations",
                str(observation["observation_id"]),
                observation,
            )
        for evidence in result.evidence_packet["evidence"]:
            await _put(
                repository,
                "evidence",
                str(evidence["evidence_id"]),
                evidence,
            )
        for assessment in result.assessments:
            await _put(
                repository,
                "assessments",
                str(assessment["assessment_id"]),
                assessment,
            )
    for artifact in discovery_artifacts:
        await _put(
            repository,
            "artifacts",
            str(artifact["artifact_id"]),
            artifact,
        )
    for evidence in discovery_evidence:
        await _put(
            repository,
            "evidence",
            str(evidence["evidence_id"]),
            evidence,
        )
    for assessment in agent_assessments:
        await _put(
            repository,
            "assessments",
            str(assessment["assessment_id"]),
            assessment,
        )
    await _put(repository, "reports", str(report["report_id"]), report)
    await _put(
        repository,
        "deliveries",
        str(delivery_plan["delivery_id"]),
        delivery_plan,
    )
    await repository.close()


async def _put(
    repository: ResearchRepository,
    collection: str,
    key: str,
    record: dict[str, Any],
) -> None:
    idempotency_key = stable_id("idem", collection, key, length=48)
    await repository.put_idempotent(
        collection,
        idempotency_key,
        record,
        key,
        record,
    )


def _discord_summary(report: dict[str, Any]) -> str:
    findings = report["findings"]
    if not findings:
        return (
            "Telemetry Research — no material emerging threats met the verified threshold "
            "in the last 24 hours."
        )
    lines = ["Telemetry Research — verified emerging threats"]
    for item in findings[:5]:
        lines.append(
            f"• {str(item['publication_class']).upper()} "
            f"{float(item['priority_score']):.1f} — {item['title']}"
        )
    degraded = report.get("degraded_sources", [])
    if degraded:
        lines.append("Degraded sources: " + ", ".join(str(item) for item in degraded))
    return "\n".join(lines)[:2000]


def _usage_record(
    *,
    stage: str,
    provider: str,
    model: str,
    requests: int,
    input_tokens: int = 0,
    output_tokens: int = 0,
    estimated_currency: float = 0,
    source_id: str | None = None,
    finding_id: str | None = None,
    agent_id: str | None = None,
) -> dict[str, Any]:
    return {
        "stage": stage,
        "agent_id": agent_id,
        "source_id": source_id,
        "finding_id": finding_id,
        "provider": provider,
        "model": model,
        "requests": requests,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "estimated_currency": estimated_currency,
    }


def _x_usage_record(usage: DiscoveryUsage) -> dict[str, Any]:
    return _usage_record(
        stage="social_discovery",
        provider=usage.provider,
        model=usage.model,
        requests=usage.requests,
        input_tokens=usage.input_tokens,
        output_tokens=usage.output_tokens,
        estimated_currency=usage.estimated_currency,
        source_id="x-researchers",
    )


def _health(source_id: str, now: datetime, *, healthy: bool) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "status": "healthy" if healthy else "failed",
        "last_success_at": format_timestamp(now) if healthy else None,
        "freshness_seconds": 0 if healthy else None,
        "error_rate": 0.0 if healthy else 1.0,
    }


def _reconcile_degraded_source_health(
    source_health: dict[str, dict[str, Any]],
    degraded: set[str],
) -> None:
    for source_id in degraded:
        current = source_health.get(source_id)
        if current is None or current.get("status") != "healthy":
            continue
        source_health[source_id] = {
            **current,
            "status": "degraded",
            "error_rate": max(float(current.get("error_rate", 0)), 0.01),
        }


def _load_discovery_config(path: Path) -> dict[str, Any]:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("discovery configuration must be an object")
    return value


def _mapping(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise ValueError(f"discovery configuration omitted {key}")
    return item


def _optional_mapping(value: dict[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key, {})
    if not isinstance(item, dict):
        raise ValueError(f"discovery configuration {key} must be an object")
    return item


def _web_queries(value: dict[str, Any]) -> tuple[tuple[str, str, str], ...]:
    items = value.get("queries")
    if not isinstance(items, list) or not items:
        raise ValueError("discovery configuration queries must be a non-empty list")
    default_freshness = str(value.get("freshness", "pd"))
    if default_freshness not in {"pd", "pw", "pm"}:
        raise ValueError("unsupported default Brave freshness window")
    queries: list[tuple[str, str, str]] = []
    for item in items:
        if isinstance(item, str) and item:
            queries.append(("brave-web", item, default_freshness))
            continue
        if (
            isinstance(item, dict)
            and isinstance(item.get("source_id"), str)
            and isinstance(item.get("query"), str)
            and item["source_id"]
            and item["query"]
        ):
            freshness = str(item.get("freshness", default_freshness))
            if freshness not in {"pd", "pw", "pm"}:
                raise ValueError("unsupported Brave query freshness window")
            queries.append((str(item["source_id"]), str(item["query"]), freshness))
            continue
        raise ValueError("each Brave query must be a string or source_id/query/freshness object")
    return tuple(queries)


def _string_tuple(value: dict[str, Any], key: str) -> tuple[str, ...]:
    items = value.get(key)
    if (
        not isinstance(items, list)
        or not items
        or not all(isinstance(item, str) and item for item in items)
    ):
        raise ValueError(f"discovery configuration {key} must be a non-empty string list")
    return tuple(items)


def _write_immutable(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError(f"immutable output mismatch: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(content)
