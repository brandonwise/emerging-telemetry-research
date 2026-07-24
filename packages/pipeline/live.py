from __future__ import annotations

import asyncio
import json
import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import yaml

from apps.report_renderer.render import TEMPLATE_REVISION, RenderedReport, render_report
from packages.common.canonical import (
    canonical_json_bytes,
    format_timestamp,
    parse_timestamp,
    sha256_hex,
    stable_id,
)
from packages.connectors.live import (
    LiveSourceArtifact,
    OfficialSourceClient,
    candidate_source_specs,
    cisa_kev_spec,
)
from packages.delivery.discord import build_discord_delivery_plan
from packages.discovery.clients import (
    BraveSearchClient,
    DiscoverySignal,
    DiscoveryUsage,
    XaiXSearchClient,
    candidate_cves,
)
from packages.pipeline.frozen import FrozenRunResult, run_frozen_fixture
from packages.security_gateway.gateway import (
    ContentSecurityGateway,
    TextArtifactMalwareScanner,
)
from packages.storage.object_store import ImmutableObjectStore
from packages.storage.repository import PostgresRepository

PUBLICATION_RANK = {"archive": 0, "daily": 1, "watch": 2, "flash": 3}


@dataclass(frozen=True, slots=True)
class LiveRunSettings:
    output_root: Path
    discord_channel_id: str
    edition: str = "morning"
    timezone: str = "America/New_York"
    discovery_config: Path = Path("config/discovery.yaml")


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


async def run_live_radar(
    settings: LiveRunSettings,
    *,
    brave_client: BraveSearchClient,
    x_search_client: XaiXSearchClient,
    official_client: OfficialSourceClient,
    object_store: ImmutableObjectStore,
    repository: PostgresRepository,
    now: datetime | None = None,
) -> LiveRunResult:
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
    promotion = _mapping(config, "promotion")
    queries = _string_tuple(brave_config, "queries")
    allowed_handles = _string_tuple(x_config, "allowed_handles")
    maximum_candidates = int(promotion.get("maximum_candidates_per_run", 6))
    maximum_findings = int(promotion.get("maximum_report_findings", 5))
    minimum_class = str(promotion.get("minimum_publication_class", "daily"))
    if minimum_class not in PUBLICATION_RANK:
        raise ValueError("invalid minimum publication class")

    signals: list[DiscoverySignal] = []
    degraded: set[str] = set()
    source_health: dict[str, dict[str, Any]] = {}
    usage: list[dict[str, Any]] = []

    for query in queries:
        try:
            signals.extend(
                await brave_client.search(
                    query,
                    freshness=str(brave_config.get("freshness", "pd")),
                    count=int(brave_config.get("maximum_results_per_query", 20)),
                )
            )
            source_health["brave-web"] = _health("brave-web", generated_at, healthy=True)
        except Exception:
            degraded.add("brave-web")
            source_health["brave-web"] = _health("brave-web", generated_at, healthy=False)
    usage.append(
        _usage_record(
            stage="web_discovery",
            provider="brave",
            model="brave-web-search-v1",
            requests=len(queries),
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
    discovery_baselines = _discovery_baselines(signals, generated_at)
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
            discovery_baseline_at=discovery_baselines.get(cve),
        )
        degraded.update(candidate_degraded)
        source_health.update(candidate_health)
        if result is not None:
            candidate_results.append(result)

    findings = sorted(
        (
            result.report["findings"][0]
            for result in candidate_results
            if result.report.get("findings")
            and PUBLICATION_RANK[str(result.report["findings"][0]["publication_class"])]
            >= PUBLICATION_RANK[minimum_class]
        ),
        key=lambda item: float(item["priority_score"]),
        reverse=True,
    )[:maximum_findings]
    usage.append(
        _usage_record(
            stage="deterministic_pipeline",
            provider="local",
            model="deterministic-code",
            requests=0,
        )
    )
    report = _aggregate_report(
        run_id=run_id,
        settings=settings,
        generated_at=generated_at,
        window_start=window_start,
        findings=findings,
        source_health=list(source_health.values()),
        degraded=degraded,
        usage=usage,
    )
    report_json_path = run_root / f"{report['report_id']}.json"
    _write_immutable(report_json_path, canonical_json_bytes(report) + b"\n")
    rendered = render_report(report, run_root / f"{report['report_id']}.html")
    delivery_plan = build_discord_delivery_plan(
        report,
        html_path=rendered.path,
        channel_id=settings.discord_channel_id,
    )
    delivery_plan_path = run_root / f"{report['report_id']}.delivery.json"
    _write_immutable(delivery_plan_path, canonical_json_bytes(delivery_plan) + b"\n")
    await _persist_run(
        repository=repository,
        run_id=run_id,
        report=report,
        candidate_results=candidate_results,
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
    )


def _existing_morning_result(
    settings: LiveRunSettings,
    generated_at: datetime,
) -> LiveRunResult | None:
    if settings.edition != "morning" or not settings.output_root.exists():
        return None
    local_date = generated_at.astimezone(ZoneInfo(settings.timezone)).date()
    candidates: list[tuple[datetime, LiveRunResult]] = []
    destination = f"discord:channel:{settings.discord_channel_id}"
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
                or delivery_plan
                != build_discord_delivery_plan(
                    report,
                    html_path=html_path,
                    channel_id=settings.discord_channel_id,
                )
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
                ),
            )
        )
    if not candidates:
        return None
    return max(candidates, key=lambda item: item[0])[1]


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
    discovery_baseline_at: datetime | None,
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
    }
    if discovery_baseline_at is not None:
        manifest["media_baseline_at"] = format_timestamp(discovery_baseline_at)
    manifest_path = candidate_root / "manifest.json"
    _write_immutable(manifest_path, canonical_json_bytes(manifest) + b"\n")
    try:
        result = run_frozen_fixture(
            manifest_path,
            candidate_root / "report",
            object_store=object_store,
            content_gateway=ContentSecurityGateway(
                malware_scanner=TextArtifactMalwareScanner()
            ),
            identifier_filter=frozenset({cve}),
            shadow_mode=False,
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
        for cve in candidate_cves((signal,)):
            scores[cve] += 2 if signal.source_id == "x-researchers" else 1
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
                        scores[cve_value.upper()] += 5
                except ValueError:
                    continue
    ranked = sorted(scores, key=lambda item: (-scores[item], item))
    return tuple(ranked[:maximum])


def _discovery_baselines(
    signals: list[DiscoverySignal],
    generated_at: datetime,
) -> dict[str, datetime]:
    baselines: dict[str, datetime] = {}
    for signal in signals:
        published_at = signal.published_at or generated_at
        for cve in candidate_cves((signal,)):
            current = baselines.get(cve)
            if current is None or published_at < current:
                baselines[cve] = published_at
    return baselines


def _aggregate_report(
    *,
    run_id: str,
    settings: LiveRunSettings,
    generated_at: datetime,
    window_start: datetime,
    findings: list[dict[str, Any]],
    source_health: list[dict[str, Any]],
    degraded: set[str],
    usage: list[dict[str, Any]],
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
    return {
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
        "usage": usage,
        "verification": {
            "all_claims_cited": True,
            "all_claims_verified": True,
            "verifier_revision": "deterministic-verifier-v1",
        },
    }


async def _persist_run(
    *,
    repository: PostgresRepository,
    run_id: str,
    report: dict[str, Any],
    candidate_results: list[FrozenRunResult],
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
    await _put(repository, "reports", str(report["report_id"]), report)
    await _put(
        repository,
        "deliveries",
        str(delivery_plan["delivery_id"]),
        delivery_plan,
    )
    await repository.close()


async def _put(
    repository: PostgresRepository,
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
            "Threat Radar — no material emerging threats met the verified threshold "
            "in the last 24 hours."
        )
    lines = ["Threat Radar — verified emerging threats"]
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
) -> dict[str, Any]:
    return {
        "stage": stage,
        "agent_id": None,
        "source_id": None,
        "finding_id": None,
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
    )


def _health(source_id: str, now: datetime, *, healthy: bool) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "status": "healthy" if healthy else "failed",
        "last_success_at": format_timestamp(now) if healthy else None,
        "freshness_seconds": 0 if healthy else None,
        "error_rate": 0.0 if healthy else 1.0,
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


def _string_tuple(value: dict[str, Any], key: str) -> tuple[str, ...]:
    items = value.get(key)
    if not isinstance(items, list) or not items or not all(
        isinstance(item, str) and item for item in items
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
