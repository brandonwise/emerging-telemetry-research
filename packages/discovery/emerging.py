from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from packages.common.canonical import (
    canonical_json_bytes,
    format_timestamp,
    sha256_hex,
    stable_id,
)
from packages.discovery.clients import CVE_PATTERN, DiscoverySignal
from packages.scoring.engine import (
    PublicationThresholds,
    ScoreComponents,
    classify,
)
from packages.storage.object_store import ImmutableObjectStore

TAG_RULES: dict[str, tuple[str, ...]] = {
    "ai": (
        r"\bai\b",
        r"\bartificial intelligence\b",
        r"\bllm\b",
        r"\blarge language model",
        r"\bmachine learning\b",
        r"\bprompt injection\b",
        r"\bmodel poisoning\b",
        r"\bhugging ?face\b",
        r"\bmcp\b",
        r"\bcopilot\b",
        r"\bagentic\b",
    ),
    "supply_chain": (
        r"supply[ -]?chain",
        r"dependency confusion",
        r"build pipeline",
        r"ci/?cd",
        r"package registry",
        r"third[ -]?party component",
    ),
    "open_source": (
        r"open[ -]?source",
        r"\bgithub\b",
        r"\bnpm\b",
        r"\bpypi\b",
        r"\bmaven\b",
        r"\bnuget\b",
        r"\brubygems\b",
        r"\bcrate\b",
    ),
    "cloud": (
        r"\bcloud\b",
        r"\baws\b",
        r"\bazure\b",
        r"\bgcp\b",
        r"\bkubernetes\b",
        r"\bserverless\b",
        r"\bsaas\b",
    ),
    "identity": (
        r"\bidentity\b",
        r"\bcredential",
        r"\bpassword",
        r"\btoken theft\b",
        r"\bsession cookie",
        r"\boauth\b",
        r"\bsso\b",
        r"\bmfa\b",
    ),
    "endpoint": (
        r"\bendpoint\b",
        r"\bwindows\b",
        r"\bmacos\b",
        r"\blinux\b",
        r"\bedr\b",
    ),
    "network": (
        r"\bnetwork\b",
        r"\bfirewall\b",
        r"\brouter\b",
        r"\bvpn\b",
        r"\bdns\b",
        r"\bedge device",
    ),
    "container": (
        r"\bcontainer",
        r"\bdocker\b",
        r"\bkubernetes\b",
        r"\bhelm\b",
    ),
    "ot_ics": (
        r"\bot\b",
        r"\bics\b",
        r"\bscada\b",
        r"industrial control",
    ),
    "mobile": (r"\bandroid\b", r"\bios\b", r"\bmobile\b"),
    "ransomware": (r"\bransomware\b", r"\bextortion\b"),
    "phishing": (r"\bphishing\b", r"\bsocial engineering\b"),
    "malware": (
        r"\bmalware\b",
        r"\bbackdoor\b",
        r"\bloader\b",
        r"\bbotnet\b",
        r"\btrojan\b",
        r"\binfostealer\b",
    ),
    "data_theft": (
        r"\bdata theft\b",
        r"\bdata exfiltration\b",
        r"\bstolen data\b",
        r"\bdata leak\b",
    ),
    "zero_day": (r"\bzero[ -]?day\b", r"\b0day\b"),
    "active_exploitation": (
        r"\bactive(?:ly)? exploit",
        r"\bknown exploitation\b",
        r"\bexploited in the wild\b",
        r"\bin[ -]?the[ -]?wild exploitation\b",
        r"\bweaponized\b",
    ),
    "proof_of_concept": (r"\bproof[ -]?of[ -]?concept\b", r"\bpoc\b"),
    "third_party": (r"\bthird[ -]?party\b", r"\bvendor\b", r"\bprovider\b"),
}

CATEGORY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "malicious_package",
        (
            r"\bmalicious package\b",
            r"\bmalicious\s+(?:[a-z0-9_-]+\s+){0,2}package\b",
            r"\btyposquat",
            r"\bdependency confusion\b",
            r"\bpackage (?:was )?compromised\b",
            r"\bpoisoned package\b",
            r"\bpoisoned\s+(?:[a-z0-9_-]+\s+){0,2}package\b",
        ),
    ),
    (
        "supply_chain",
        (
            r"supply[ -]?chain",
            r"\bbuild pipeline\b",
            r"\bci/?cd\b",
            r"\bdependency\b",
            r"\bpackage registry\b",
        ),
    ),
    (
        "credential_exposure",
        (
            r"\bcredential",
            r"\bpassword",
            r"\bsecret leak",
            r"\bapi key",
            r"\btoken theft\b",
            r"\bsession cookie",
        ),
    ),
    (
        "campaign",
        (
            r"\bcampaign\b",
            r"\bransomware\b",
            r"\bphishing\b",
            r"\bmalware\b",
            r"\bbotnet\b",
            r"\bespionage\b",
        ),
    ),
    (
        "vendor_incident",
        (
            r"\bvendor (?:breach|incident|compromise)\b",
            r"\bprovider (?:breach|incident|compromise)\b",
            r"\bthird[ -]?party (?:breach|incident|compromise)\b",
        ),
    ),
    (
        "active_exploitation",
        TAG_RULES["active_exploitation"] + TAG_RULES["zero_day"],
    ),
    (
        "vulnerability",
        (
            r"\bvulnerab",
            r"\bremote code execution\b",
            r"\bprivilege escalation\b",
            r"\bauthentication bypass\b",
            r"\bsecurity flaw\b",
            r"\bcve-\d{4}-\d{4,}\b",
        ),
    ),
    (
        "infrastructure",
        (
            r"\bcommand and control\b",
            r"\bc2 infrastructure\b",
            r"\bmalicious domain\b",
            r"\bexposed server\b",
            r"\bbotnet infrastructure\b",
        ),
    ),
)

STOP_WORDS = {
    "about",
    "active",
    "after",
    "against",
    "and",
    "are",
    "attack",
    "attacker",
    "attacks",
    "before",
    "being",
    "critical",
    "could",
    "cyber",
    "cybersecurity",
    "discovered",
    "emerging",
    "exploit",
    "exploited",
    "exploitation",
    "flaw",
    "for",
    "from",
    "has",
    "have",
    "how",
    "into",
    "its",
    "latest",
    "more",
    "new",
    "not",
    "over",
    "report",
    "reported",
    "researchers",
    "security",
    "signal",
    "than",
    "that",
    "the",
    "their",
    "they",
    "this",
    "threat",
    "through",
    "under",
    "vulnerability",
    "vulnerabilities",
    "was",
    "were",
    "will",
    "using",
    "with",
    "you",
    "your",
}


@dataclass(frozen=True, slots=True)
class Taxonomy:
    category: str
    tags: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PreparedSignal:
    signal: DiscoverySignal
    taxonomy: Taxonomy
    origin: str
    evidence: dict[str, Any]
    artifact: dict[str, Any]
    source_evidence: dict[str, Any]


def classify_taxonomy(
    title: str,
    summary: str,
    *,
    identifiers: tuple[str, ...] = (),
) -> Taxonomy:
    text = f"{title}\n{summary}".lower()
    category = "other"
    for candidate, patterns in CATEGORY_RULES:
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
            category = candidate
            break
    tags = {
        tag
        for tag, patterns in TAG_RULES.items()
        if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns)
    }
    if category in {"supply_chain", "malicious_package"}:
        tags.add("supply_chain")
    if category == "credential_exposure":
        tags.add("identity")
    if category == "active_exploitation":
        tags.add("active_exploitation")
    if any(CVE_PATTERN.fullmatch(item) for item in identifiers):
        tags.add("cve")
    else:
        tags.add("pre_cve")
    return Taxonomy(category=category, tags=tuple(sorted(tags)))


def prepare_discovery_signals(
    signals: list[DiscoverySignal],
    *,
    generated_at: datetime,
    object_store: ImmutableObjectStore,
) -> tuple[PreparedSignal, ...]:
    prepared: list[PreparedSignal] = []
    seen: set[tuple[str, str]] = set()
    for signal in signals:
        dedupe_key = (signal.source_id, signal.url)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        source_type = "x_post" if signal.source_id == "x-researchers" else "website"
        origin = _origin(signal)
        taxonomy = classify_taxonomy(
            signal.title,
            "\n".join(item for item in (signal.summary, signal.rationale) if item is not None),
            identifiers=signal.identifiers,
        )
        excerpt = signal.summary[:1200]
        source_label = (
            f"@{signal.source_handle} on X"
            if signal.source_handle
            else urlsplit(signal.url).hostname or signal.source_id
        )
        claim = _bounded(f"{source_label} reported: {excerpt}", 800)
        published_at = (
            format_timestamp(signal.published_at.astimezone(UTC))
            if signal.published_at is not None
            else None
        )
        payload = {
            "source_id": signal.source_id,
            "source_type": source_type,
            "title": signal.title,
            "url": signal.url,
            "summary": excerpt,
            "rationale": signal.rationale,
            "published_at": published_at,
            "identifiers": list(signal.identifiers),
            "source_handle": signal.source_handle,
        }
        stored = object_store.put(
            canonical_json_bytes(payload),
            {
                "source_id": signal.source_id,
                "artifact_type": "discovery_signal",
                "canonical_uri": signal.url,
            },
        )
        retrieved_at = format_timestamp(generated_at)
        artifact_id = stable_id(
            "ra",
            signal.source_id,
            signal.url,
            stored.content_hash,
            retrieved_at,
        )
        evidence_id = stable_id("ev", artifact_id, claim)
        evidence = {
            "evidence_id": evidence_id,
            "source_id": signal.source_id,
            "source_role": ("researcher_observation" if source_type == "x_post" else "precursor"),
            "canonical_uri": signal.url,
            "retrieved_at": retrieved_at,
            "published_at": published_at,
            "content_hash": stored.content_hash,
            "sanitized_hash": sha256_hex(f"{signal.title}\n{excerpt}"),
            "excerpt": excerpt,
            "claims_supported": [claim],
            "injection_risk": "low",
            "independence_group": origin,
        }
        source_evidence = {
            "evidence_id": evidence_id,
            "source_id": signal.source_id,
            "source_type": source_type,
            "title": signal.title,
            "url": signal.url,
            "published_at": published_at,
            "retrieved_at": retrieved_at,
            "excerpt": excerpt,
            "source_handle": signal.source_handle,
        }
        artifact = {
            "schema_version": "1.0",
            "artifact_id": artifact_id,
            "source_id": signal.source_id,
            "canonical_uri": signal.url,
            "retrieved_at": retrieved_at,
            "content_hash": stored.content_hash,
            "object_key": stored.key,
            "size": stored.size,
            "version_id": stored.version_id,
        }
        prepared.append(
            PreparedSignal(
                signal=signal,
                taxonomy=taxonomy,
                origin=origin,
                evidence=evidence,
                artifact=artifact,
                source_evidence=source_evidence,
            )
        )
    return tuple(prepared)


def cluster_non_cve_signals(
    signals: tuple[PreparedSignal, ...],
) -> tuple[tuple[PreparedSignal, ...], ...]:
    clusters: list[list[PreparedSignal]] = []
    for signal in sorted(
        (item for item in signals if not _cves(item.signal)),
        key=lambda item: (
            item.signal.published_at or datetime.max.replace(tzinfo=UTC),
            item.signal.title,
        ),
    ):
        for cluster in clusters:
            # Complete-link clustering prevents a generic middle item from joining
            # otherwise unrelated stories into one high-confidence mega-cluster.
            if all(_related(signal, existing) for existing in cluster):
                cluster.append(signal)
                break
        else:
            clusters.append([signal])
    return tuple(
        tuple(cluster)
        for cluster in sorted(
            clusters,
            key=lambda items: (
                -len({item.origin for item in items}),
                -len(items),
                items[0].signal.title,
            ),
        )
    )


def build_emerging_finding(
    cluster: tuple[PreparedSignal, ...],
    *,
    generated_at: datetime,
    thresholds: PublicationThresholds,
) -> dict[str, Any]:
    if not cluster:
        raise ValueError("emerging signal cluster cannot be empty")
    ordered = sorted(
        cluster,
        key=lambda item: (
            item.signal.published_at or generated_at,
            item.signal.title,
        ),
    )
    origins = {item.origin for item in ordered}
    category = Counter(item.taxonomy.category for item in ordered).most_common(1)[0][0]
    tags = sorted({tag for item in ordered for tag in item.taxonomy.tags})
    source_count = len(origins)
    score = _emerging_score(category, set(tags), len(ordered), source_count)
    publication_class = classify(
        score,
        citations_present=True,
        flash_confirmation_rule=False,
        thresholds=thresholds,
    )
    first_seen = min(item.signal.published_at or generated_at for item in ordered)
    confidence_level = "low" if source_count == 1 else ("medium" if source_count == 2 else "high")
    probability = {1: 0.45, 2: 0.7}.get(source_count, 0.85)
    cluster_id = stable_id(
        "cl",
        category,
        "|".join(sorted(item.origin for item in ordered)),
        "|".join(sorted(item.signal.url for item in ordered)),
    )
    claims = [
        {
            "claim_id": stable_id("claim", str(item.evidence["evidence_id"])),
            "text": str(item.evidence["claims_supported"][0]),
            "certainty": "reported",
            "evidence_ids": [str(item.evidence["evidence_id"])],
            "verification_status": "verified",
        }
        for item in ordered
    ]
    return {
        "schema_version": "1.0",
        "finding_id": stable_id("fd", cluster_id),
        "cluster_id": cluster_id,
        "title": ordered[0].signal.title,
        "why_now": (
            f"{len(ordered)} fresh source-native signal(s) from {source_count} independent "
            "origin(s) surfaced without an authoritative CVE mapping. The item is preserved "
            "as reported intelligence while corroboration continues."
        ),
        "category": category,
        "tags": tags,
        "emergence_stage": "watch_signal" if source_count == 1 else "credible_emerging",
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
                f"{source_count} independent source origin(s); source statements are verified "
                "against preserved discovery evidence, but the underlying event is not yet "
                "authoritatively confirmed."
            ),
        },
        "momentum": "rising" if len(ordered) == 1 else "accelerating",
        "novelty": "exceptional",
        "lead_time_hours": None,
        "first_observed_at": format_timestamp(first_seen),
        "last_updated_at": format_timestamp(generated_at),
        "affected": [],
        "exploit_status": (
            "exploitation_suspected" if "active_exploitation" in tags else "unknown"
        ),
        "organization_relevance": (
            "No deterministic inventory match is available yet; validate exposure against "
            "the cited source-native signal."
        ),
        "known": [str(item["text"]) for item in claims],
        "unknown": [
            "No authoritative CVE or equivalent advisory mapping was available at collection time.",
            "The source reports have not yet established the full affected scope or root cause.",
        ],
        "contradictions": [],
        "defensive_actions": [_defensive_action(category)],
        "mappings": [],
        "indicators": [],
        "claims": claims,
        "source_evidence": [item.source_evidence for item in ordered],
        "skeptic_summary": (
            "This is an early source-native signal, not a confirmed vulnerability record. "
            "Treat scope, attribution, and exploitation details as provisional."
        ),
        "next_check_at": format_timestamp(
            generated_at + timedelta(hours=2 if source_count > 1 else 4)
        ),
    }


def related_cves(
    cluster: tuple[PreparedSignal, ...],
    signals: tuple[PreparedSignal, ...],
) -> tuple[str, ...]:
    matches: set[str] = set()
    for candidate in signals:
        candidate_cves = _cves(candidate.signal)
        if candidate_cves and any(_related(item, candidate) for item in cluster):
            matches.update(candidate_cves)
    return tuple(sorted(matches))


def enrich_cve_finding(
    finding: dict[str, Any],
    *,
    cve: str,
    signals: tuple[PreparedSignal, ...],
    related_signals: tuple[PreparedSignal, ...] = (),
) -> dict[str, Any]:
    matching_by_evidence_id = {
        str(item.evidence["evidence_id"]): item
        for item in [
            *(item for item in signals if cve in _cves(item.signal)),
            *related_signals,
        ]
    }
    matching = list(matching_by_evidence_id.values())
    combined_text = "\n".join(
        [
            str(finding.get("title", "")),
            *(str(item) for item in finding.get("known", [])),
        ]
    )
    taxonomy = classify_taxonomy(combined_text, "", identifiers=(cve,))
    tags = set(taxonomy.tags)
    for item in matching:
        tags.update(item.taxonomy.tags)
    result = dict(finding)
    result["tags"] = sorted(tags)
    result["source_evidence"] = [item.source_evidence for item in matching]
    return result


def referenced_discovery_records(
    findings: list[dict[str, Any]],
    signals: tuple[PreparedSignal, ...],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    evidence_ids = {
        str(source["evidence_id"])
        for finding in findings
        for source in finding.get("source_evidence", [])
        if isinstance(source, dict) and source.get("evidence_id")
    }
    evidence = [
        item.evidence for item in signals if str(item.evidence["evidence_id"]) in evidence_ids
    ]
    artifacts = [
        item.artifact for item in signals if str(item.evidence["evidence_id"]) in evidence_ids
    ]
    return evidence, artifacts


def _emerging_score(
    category: str,
    tags: set[str],
    signal_count: int,
    source_count: int,
) -> ScoreComponents:
    impact = {
        "malicious_package": 21.0,
        "supply_chain": 20.0,
        "credential_exposure": 20.0,
        "campaign": 19.0,
        "vendor_incident": 19.0,
        "active_exploitation": 21.0,
        "vulnerability": 18.0,
        "infrastructure": 17.0,
        "other": 14.0,
    }[category]
    if "active_exploitation" in tags or "zero_day" in tags:
        exploitability = 15.0
    elif {"malware", "ransomware", "proof_of_concept"}.intersection(tags):
        exploitability = 12.0
    else:
        exploitability = 8.0
    evidence_strength = min(15.0, 8.0 + max(0, source_count - 1) * 3.0)
    momentum = min(
        15.0,
        6.0 + max(0, signal_count - 1) * 2.0 + max(0, source_count - 1) * 2.0,
    )
    return ScoreComponents(
        impact=impact,
        exploitability=exploitability,
        evidence_strength=evidence_strength,
        momentum=momentum,
        novelty_lead_time=15.0,
        organization_relevance=0.0,
        penalties=-8.0 if source_count == 1 else 0.0,
        reasons=(
            f"{signal_count} source-native signal(s)",
            f"{source_count} independent origin(s)",
            "no CVE or authoritative advisory mapping at collection time",
        ),
    )


def _defensive_action(category: str) -> dict[str, Any]:
    action = {
        "malicious_package": (
            "Search dependency inventories and recent build logs for the cited package or "
            "repository; quarantine only after confirming a match."
        ),
        "supply_chain": (
            "Review recent dependency, build-system, and third-party changes related to the "
            "cited source; preserve provenance before taking action."
        ),
        "credential_exposure": (
            "Review identity telemetry for matching credential or session abuse indicators; "
            "rotate credentials only when exposure is confirmed."
        ),
        "campaign": (
            "Monitor the cited campaign behaviors and indicators in existing telemetry while "
            "the report is independently corroborated."
        ),
        "vendor_incident": (
            "Identify dependencies on the cited vendor and review its primary incident guidance."
        ),
    }.get(
        category,
        "Monitor the cited primary sources and validate local exposure before making changes.",
    )
    return {
        "priority": "monitor",
        "action": action,
        "reversible": True,
        "requires_approval": False,
    }


def _related(left: PreparedSignal, right: PreparedSignal) -> bool:
    if left.signal.url == right.signal.url:
        return True
    categories = {left.taxonomy.category, right.taxonomy.category}
    if len(categories) > 1 and categories != {"active_exploitation", "vulnerability"}:
        return False
    left_tokens = _title_tokens(left.signal)
    right_tokens = _title_tokens(right.signal)
    intersection = left_tokens.intersection(right_tokens)
    union = left_tokens.union(right_tokens)
    smaller = min(len(left_tokens), len(right_tokens))
    return (
        "other" not in categories
        and len(intersection) >= 2
        and len(intersection) / max(smaller, 1) >= 0.5
        and len(intersection) / max(len(union), 1) >= 0.25
    )


def _title_tokens(signal: DiscoverySignal) -> set[str]:
    text = signal.title.lower()
    return {
        token
        for token in re.findall(r"[a-z0-9][a-z0-9_-]{2,}", text)
        if token not in STOP_WORDS and not CVE_PATTERN.fullmatch(token)
    }


def _origin(signal: DiscoverySignal) -> str:
    if signal.source_handle:
        return f"x:@{signal.source_handle.lower()}"
    hostname = (urlsplit(signal.url).hostname or signal.source_id).lower()
    return f"web:{hostname}"


def _cves(signal: DiscoverySignal) -> set[str]:
    return {
        identifier.upper() for identifier in signal.identifiers if CVE_PATTERN.fullmatch(identifier)
    }


def _bounded(value: str, maximum: int) -> str:
    return value if len(value) <= maximum else value[: maximum - 1].rstrip() + "…"
