from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from apps.report_renderer.render import RenderedReport, render_report
from packages.agents.shadow import run_shadow_review_chain
from packages.audit.ledger import AuditLedger
from packages.common.canonical import (
    canonical_json_bytes,
    format_timestamp,
    parse_timestamp,
    sha256_hex,
    stable_id,
)
from packages.connectors.tier0 import parse_tier0
from packages.contracts.validation import validate_payload
from packages.lineage.graph import (
    LineageEdge,
    independent_source_count,
    validate_lineage,
)
from packages.normalization.entities import normalize_entities
from packages.scoring.engine import PublicationClass, ScoreComponents, classify
from packages.scoring.features import ClusterSignals, compute_score
from packages.security_gateway.gateway import ContentSecurityGateway
from packages.storage.object_store import ImmutableObjectStore, LocalImmutableObjectStore
from packages.telemetry.runtime import RadarTelemetry
from packages.verification.claims import verify_report_claims

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


@dataclass(frozen=True, slots=True)
class FrozenRunResult:
    report: dict[str, Any]
    evidence_packet: dict[str, Any]
    assessments: tuple[dict[str, Any], ...]
    observations: tuple[dict[str, Any], ...]
    rendered: RenderedReport
    audit_path: Path
    report_json_path: Path


def run_frozen_fixture(
    manifest_path: Path,
    output_root: Path,
    *,
    object_store_root: Path | None = None,
    object_store: ImmutableObjectStore | None = None,
    content_gateway: ContentSecurityGateway | None = None,
    identifier_filter: frozenset[str] | None = None,
    shadow_mode: bool = True,
) -> FrozenRunResult:
    manifest = _load_manifest(manifest_path)
    run_id = str(manifest["run_id"])
    generated_at = parse_timestamp(str(manifest["generated_at"]))
    generated_text = format_timestamp(generated_at)
    ledger = AuditLedger(run_id=run_id, timestamp=generated_text)
    telemetry = RadarTelemetry.current("threat-radar-frozen-pipeline")
    store = object_store or LocalImmutableObjectStore(object_store_root or output_root / "objects")
    gateway = content_gateway or ContentSecurityGateway()
    observations: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    source_health: list[dict[str, Any]] = []
    degraded_sources: list[str] = []
    source_to_evidence: dict[str, list[str]] = {}
    risks: list[str] = []

    ledger.append(
        "run.created",
        actor="orchestrator",
        input_hash=sha256_hex(canonical_json_bytes(manifest)),
        output_hash=sha256_hex(run_id),
    )
    fixture_root = manifest_path.parent.resolve()
    for source in manifest["sources"]:
        source_id = str(source["source_id"])
        if source.get("available") is False:
            degraded_sources.append(source_id)
            source_health.append(_source_health(source_id, "failed", None, 1.0))
            ledger.append(
                "source.unavailable",
                actor="collector",
                decision="allow",
                reason_code="partial_report",
                details={"source_id": source_id},
            )
            telemetry.source_fetch(source_id=source_id, status="degraded")
            continue
        relative_file = Path(str(source["file"]))
        path = (fixture_root / relative_file).resolve()
        if not path.is_relative_to(fixture_root) or not path.is_file():
            raise ValueError(f"fixture source file is invalid: {relative_file}")
        raw = path.read_bytes()
        retrieved_at = parse_timestamp(str(source["retrieved_at"]))
        stored = store.put(
            raw,
            {
                "run_id": run_id,
                "source_id": source_id,
                "canonical_uri": str(source["canonical_uri"]),
                "retrieved_at": format_timestamp(retrieved_at),
            },
        )
        ledger.append(
            "artifact.captured",
            actor="collector",
            input_hash=sha256_hex(str(source["canonical_uri"])),
            output_hash=stored.content_hash,
            details={"source_id": source_id, "object_key": stored.key},
        )
        telemetry.source_fetch(source_id=source_id, status="ok")
        decision = gateway.process(raw, str(source["content_type"]))
        risks.append(decision.content_risk)
        ledger.append(
            "artifact.sanitized",
            actor="content-security-gateway",
            input_hash=decision.original_hash,
            output_hash=decision.sanitized_hash,
            decision=decision.disposition,
            reason_code=f"content_risk_{decision.content_risk}",
            details={
                "source_id": source_id,
                "detected_patterns": list(decision.detected_patterns),
            },
        )
        if decision.content_risk != "low":
            telemetry.security_event(
                category="source_content",
                risk=decision.content_risk,
                disposition=decision.disposition,
            )
        if decision.disposition == "blocked":
            degraded_sources.append(source_id)
            source_health.append(_source_health(source_id, "degraded", generated_text, 1.0))
            continue
        parsed = parse_tier0(source_id, raw, retrieved_at)
        if identifier_filter is not None:
            normalized_filter = {item.upper() for item in identifier_filter}
            parsed = tuple(
                draft
                for draft in parsed
                if normalized_filter.intersection(
                    identifier.upper() for identifier in draft.identifiers
                )
            )
        for draft in parsed:
            contract = draft.to_contract()
            validate_payload("observation.schema.json", contract)
            observations.append(contract)
            evidence_id = stable_id(
                "ev",
                str(contract["observation_id"]),
                decision.original_hash,
            )
            evidence_item = {
                "evidence_id": evidence_id,
                "source_id": source_id,
                "source_role": contract["source_role"],
                "canonical_uri": str(source["canonical_uri"]),
                "retrieved_at": contract["observed_at"],
                "published_at": contract["published_at"],
                "content_hash": decision.original_hash,
                "sanitized_hash": decision.sanitized_hash,
                "excerpt": "\n".join(str(item) for item in contract["claims"])[:12_000],
                "claims_supported": contract["claims"],
                "injection_risk": decision.content_risk,
                "independence_group": str(source["independence_group"]),
            }
            evidence.append(evidence_item)
            source_to_evidence.setdefault(source_id, []).append(evidence_id)
        source_health.append(_source_health(source_id, "healthy", generated_text, 0.0))
        ledger.append(
            "observations.extracted",
            actor="deterministic-extractor",
            input_hash=decision.sanitized_hash,
            output_hash=sha256_hex(canonical_json_bytes([item.to_contract() for item in parsed])),
            details={"source_id": source_id, "count": len(parsed)},
        )

    identifiers = sorted(
        {
            str(identifier)
            for observation in observations
            for identifier in observation["identifiers"]
        }
    )
    entities = normalize_entities(identifiers)
    cves = [item.canonical_name for item in entities if item.type == "cve"]
    if not cves:
        raise ValueError("frozen vertical slice requires at least one CVE")
    cluster_key = cves[0]
    cluster_id = stable_id("cl", cluster_key)
    lineage = _build_lineage(manifest, evidence, source_to_evidence)
    evidence_ids = tuple(str(item["evidence_id"]) for item in evidence)
    validate_lineage(evidence_ids, lineage)
    independent_count = independent_source_count(evidence_ids, lineage)
    first_observed = min(
        parse_timestamp(str(item["published_at"] or item["retrieved_at"])) for item in evidence
    )
    media_baseline_value = manifest.get("media_baseline_at")
    media_baseline = (
        parse_timestamp(str(media_baseline_value)) if media_baseline_value is not None else None
    )
    content_risk = max(risks or ["low"], key=RISK_ORDER.__getitem__)
    signals = ClusterSignals(
        first_observed_at=first_observed,
        evidence_count=len(evidence),
        independent_source_count=independent_count,
        direct_artifact_count=sum(
            1
            for item in evidence
            if item["source_role"] in {"direct_artifact", "authoritative_advisory"}
        ),
        cvss_base_score=_maximum_optional(observations, "cvss_base_score"),
        epss_probability=_maximum_optional(observations, "epss_probability"),
        known_exploited=any(bool(item["known_exploited"]) for item in observations),
        media_baseline_at=media_baseline,
        organization_match=_organization_match(observations, manifest.get("inventory", [])),
        content_risk=content_risk,
    )
    score = compute_score(signals)
    flash_confirmation = signals.known_exploited and independent_count >= 2
    publication_class = classify(score, flash_confirmation_rule=flash_confirmation)
    packet = {
        "schema_version": "1.0",
        "packet_id": stable_id("ep", cluster_id, run_id),
        "cluster_id": cluster_id,
        "generated_at": generated_text,
        "policy_revision": "policy-v1",
        "sanitizer_revision": "gateway-v1",
        "entities": [item.to_contract() for item in entities],
        "evidence": evidence,
        "source_lineage": [item.to_contract() for item in lineage],
        "deterministic_features": {
            "independent_source_count": independent_count,
            "evidence_count": len(evidence),
            "known_exploited": signals.known_exploited,
            "media_baseline_present": media_baseline is not None,
        },
        "preliminary_score": score.total,
        "content_risk": content_risk,
    }
    validate_payload("evidence-packet.schema.json", packet)
    ledger.append(
        "cluster.scored",
        actor="scoring-engine",
        input_hash=sha256_hex(canonical_json_bytes(packet)),
        output_hash=sha256_hex(canonical_json_bytes(asdict(score))),
        details={"cluster_id": cluster_id, "score": score.total},
    )
    assessments = run_shadow_review_chain(
        packet,
        created_at=generated_at,
        recommended_disposition=publication_class.value,
    )
    ledger.append(
        "cluster.reviewed",
        actor="bounded-agent-chain",
        input_hash=sha256_hex(canonical_json_bytes(packet)),
        output_hash=sha256_hex(canonical_json_bytes(assessments)),
        details={"roles": [item["agent_role"] for item in assessments]},
    )
    finding = _build_finding(
        cluster_id=cluster_id,
        cve=cluster_key,
        observations=observations,
        evidence=evidence,
        score=score,
        signals=signals,
        publication_class=publication_class,
        generated_at=generated_at,
        assessments=assessments,
        shadow_mode=shadow_mode,
    )
    report = _build_report(
        manifest=manifest,
        generated_text=generated_text,
        finding=finding,
        source_health=source_health,
        degraded_sources=degraded_sources,
        shadow_mode=shadow_mode,
    )
    verification = verify_report_claims(report, packet, verifier_revision="verifier-v1")
    if not verification.passed:
        raise ValueError(
            "report verification failed: "
            f"rejected={verification.rejected_claim_ids}, "
            f"missing={verification.missing_evidence_ids}"
        )
    report = verification.report
    validate_payload("report.schema.json", report)
    ledger.append(
        "report.verified",
        actor="citation-verifier",
        input_hash=sha256_hex(canonical_json_bytes(finding)),
        output_hash=sha256_hex(canonical_json_bytes(report)),
    )

    output_root.mkdir(parents=True, exist_ok=True)
    report_json_path = output_root / f"{report['report_id']}.json"
    _write_immutable(report_json_path, canonical_json_bytes(report) + b"\n")
    rendered = render_report(report, output_root / f"{report['report_id']}.html")
    ledger.append(
        "report.rendered",
        actor="publisher",
        input_hash=rendered.report_json_hash,
        output_hash=rendered.rendered_html_hash,
        decision="allow",
        reason_code=(
            "shadow_mode_no_external_delivery"
            if shadow_mode
            else "verified_live_report_ready"
        ),
    )
    audit_path = output_root / f"{run_id}.audit.jsonl"
    _write_immutable(audit_path, ledger.json_lines())
    telemetry.workflow_run(
        mode="frozen_fixture" if shadow_mode else "live_candidate",
        status="degraded" if degraded_sources else "ok",
    )
    return FrozenRunResult(
        report=report,
        evidence_packet=packet,
        assessments=assessments,
        observations=tuple(observations),
        rendered=rendered,
        audit_path=audit_path,
        report_json_path=report_json_path,
    )


def _load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("fixture manifest must be an object")
    required = {"run_id", "generated_at", "edition", "window", "sources"}
    missing = required - value.keys()
    if missing:
        raise ValueError(f"fixture manifest missing fields: {sorted(missing)}")
    if not isinstance(value["sources"], list):
        raise ValueError("fixture sources must be a list")
    return value


def _build_lineage(
    manifest: dict[str, Any],
    evidence: list[dict[str, Any]],
    source_to_evidence: dict[str, list[str]],
) -> tuple[LineageEdge, ...]:
    declared = {
        str(item["source_id"]): item
        for item in manifest.get("lineage", [])
        if isinstance(item, dict) and "source_id" in item
    }
    edges: list[LineageEdge] = []
    for item in evidence:
        source_id = str(item["source_id"])
        declaration = declared.get(source_id)
        if not declaration:
            edges.append(LineageEdge(str(item["evidence_id"]), None, "original"))
            continue
        parent_source = str(declaration["parent_source_id"])
        parents = source_to_evidence.get(parent_source)
        if not parents:
            raise ValueError(f"lineage parent source has no evidence: {parent_source}")
        edges.append(
            LineageEdge(
                str(item["evidence_id"]),
                parents[0],
                str(declaration["relationship"]),
                float(declaration.get("confidence", 1)),
            )
        )
    return tuple(edges)


def _build_finding(
    *,
    cluster_id: str,
    cve: str,
    observations: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    score: ScoreComponents,
    signals: ClusterSignals,
    publication_class: PublicationClass,
    generated_at: Any,
    assessments: tuple[dict[str, Any], ...],
    shadow_mode: bool,
) -> dict[str, Any]:
    claims = [
        {
            "claim_id": stable_id("claim", str(item["evidence_id"]), str(claim)),
            "text": str(claim),
            "certainty": "confirmed" if signals.known_exploited else "observed",
            "evidence_ids": [str(item["evidence_id"])],
            "verification_status": "pending",
        }
        for item in evidence
        for claim in item["claims_supported"]
    ]
    known = [str(item["text"]) for item in claims]
    affected_map: dict[tuple[str, str, str | None], dict[str, Any]] = {}
    for observation in observations:
        for item in observation["affected"]:
            key = (str(item["type"]), str(item["name"]), item.get("version_range"))
            affected_map[key] = item
    mappings = [
        {"scheme": _mapping_scheme(identifier), "identifier": identifier}
        for identifier in sorted(
            {
                str(identifier)
                for observation in observations
                for identifier in observation["identifiers"]
            }
        )
    ]
    confidence_level = "high" if signals.independent_source_count >= 2 else "medium"
    probability = 0.9 if confidence_level == "high" else 0.65
    first_observed_text = format_timestamp(signals.first_observed_at)
    last_updated = format_timestamp(generated_at)
    lead_time = (
        round((signals.media_baseline_at - signals.first_observed_at).total_seconds() / 3600, 2)
        if signals.media_baseline_at
        else None
    )
    skeptic = next(item for item in assessments if item["agent_role"] == "skeptic")
    return {
        "schema_version": "1.0",
        "finding_id": stable_id("fd", cluster_id),
        "cluster_id": cluster_id,
        "title": (
            f"Known exploitation signal for {cve}"
            if signals.known_exploited
            else f"Emerging vulnerability signal for {cve}"
        ),
        "why_now": (
            (
                "Authoritative exploitation evidence and independent technical records "
                "converged before a media baseline was present."
                if signals.media_baseline_at is None
                else "Authoritative exploitation evidence remains material, but broad "
                "reporting now reduces the novelty score."
            )
            if shadow_mode
            else (
                "Fresh web or X discovery signals triggered verification against CISA and "
                "independent authoritative vulnerability records."
                if signals.media_baseline_at is not None
                else "Recent authoritative source updates triggered independent verification "
                "across vulnerability and exploitability records."
            )
        ),
        "category": "active_exploitation" if signals.known_exploited else "vulnerability",
        "emergence_stage": "confirmed" if signals.known_exploited else "credible_emerging",
        "publication_class": publication_class.value,
        "priority_score": score.total,
        "score_components": {
            "impact": score.impact,
            "exploitability": score.exploitability,
            "evidence_strength": score.evidence_strength,
            "momentum": score.momentum,
            "novelty_lead_time": score.novelty_lead_time,
            "organization_relevance": score.organization_relevance,
            "penalties": score.penalties,
        },
        "confidence": {
            "level": confidence_level,
            "probability": probability,
            "rationale": (
                f"{signals.independent_source_count} independent origins support the cluster; "
                "the score remains deterministic."
            ),
        },
        "momentum": "accelerating" if signals.evidence_count >= 4 else "rising",
        "novelty": "high" if score.novelty_lead_time >= 10 else "low",
        "lead_time_hours": lead_time,
        "first_observed_at": first_observed_text,
        "last_updated_at": last_updated,
        "affected": list(affected_map.values()),
        "exploit_status": "known_exploited" if signals.known_exploited else "unknown",
        "organization_relevance": (
            (
                "The demo inventory contains a matching product or package."
                if shadow_mode
                else "The configured inventory contains a matching product or package."
            )
            if signals.organization_match
            else (
                "No demo-inventory match was found."
                if shadow_mode
                else "No configured inventory match was found."
            )
        ),
        "known": known,
        "unknown": [
            (
                "The fixture does not establish exposure outside the listed affected "
                "product or package."
                if shadow_mode
                else "The collected evidence does not establish exposure outside the "
                "listed affected product or package."
            )
        ],
        "contradictions": [],
        "defensive_actions": [
            {
                "priority": "today",
                "action": (
                    "Check inventory for the cited product or package and review vendor guidance."
                ),
                "reversible": True,
                "requires_approval": False,
            }
        ],
        "mappings": mappings,
        "indicators": [],
        "claims": claims,
        "skeptic_summary": str(skeptic["judgment"]),
        "next_check_at": format_timestamp(generated_at + timedelta(hours=1)),
    }


def _build_report(
    *,
    manifest: dict[str, Any],
    generated_text: str,
    finding: dict[str, Any],
    source_health: list[dict[str, Any]],
    degraded_sources: list[str],
    shadow_mode: bool,
) -> dict[str, Any]:
    window = manifest["window"]
    report_id = stable_id("rp", str(manifest["run_id"]), str(manifest["edition"]))
    return {
        "schema_version": "1.0",
        "report_id": report_id,
        "edition": manifest["edition"],
        "generated_at": generated_text,
        "window": {
            "start": str(window["start"]),
            "end": str(window["end"]),
            "timezone": str(window["timezone"]),
        },
        "executive_summary": (
            f"One {finding['publication_class']} finding met the "
            f"{'shadow' if shadow_mode else 'verified'} publication gate. "
            f"Priority score: {finding['priority_score']:.1f}."
        ),
        "findings": [finding],
        "degraded_sources": sorted(set(degraded_sources)),
        "source_health": sorted(source_health, key=lambda item: item["source_id"]),
        "usage": [
            {
                "stage": "deterministic_pipeline",
                "agent_id": None,
                "source_id": None,
                "finding_id": finding["finding_id"],
                "provider": "local",
                "model": "deterministic-code",
                "requests": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "estimated_currency": 0,
            },
            {
                "stage": (
                    "shadow_review_chain"
                    if shadow_mode
                    else "deterministic_review_chain"
                ),
                "agent_id": "specialist-skeptic-verifier-coordinator",
                "source_id": None,
                "finding_id": finding["finding_id"],
                "provider": "fixture" if shadow_mode else "local",
                "model": (
                    "deterministic-shadow-fixture"
                    if shadow_mode
                    else "deterministic-review-v1"
                ),
                "requests": 4,
                "input_tokens": 0,
                "output_tokens": 0,
                "estimated_currency": 0,
            },
        ],
        "verification": {
            "all_claims_cited": False,
            "all_claims_verified": False,
            "verifier_revision": "pending",
        },
    }


def _source_health(
    source_id: str,
    status: str,
    last_success_at: str | None,
    error_rate: float,
) -> dict[str, Any]:
    return {
        "source_id": source_id,
        "status": status,
        "last_success_at": last_success_at,
        "freshness_seconds": 0 if last_success_at else None,
        "error_rate": error_rate,
    }


def _maximum_optional(observations: list[dict[str, Any]], field: str) -> float | None:
    values = [float(item[field]) for item in observations if item.get(field) is not None]
    return max(values) if values else None


def _organization_match(observations: list[dict[str, Any]], inventory: object) -> bool:
    if not isinstance(inventory, list):
        return False
    normalized_inventory = {str(item).strip().lower() for item in inventory}
    return any(
        str(affected["name"]).strip().lower() in normalized_inventory
        for observation in observations
        for affected in observation["affected"]
    )


def _mapping_scheme(identifier: str) -> str:
    upper = identifier.upper()
    if upper.startswith("CVE-"):
        return "CVE"
    if upper.startswith("GHSA-"):
        return "GHSA"
    if upper.startswith("OSV-"):
        return "OSV"
    if upper.startswith("PKG:"):
        return "PURL"
    return "OTHER"


def _write_immutable(path: Path, content: bytes) -> None:
    if path.exists():
        if path.read_bytes() != content:
            raise ValueError(f"immutable output mismatch: {path}")
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(content)
