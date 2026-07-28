from datetime import UTC, datetime, timedelta
from pathlib import Path

from packages.contracts.validation import validate_payload
from packages.discovery.clients import DiscoverySignal
from packages.discovery.emerging import (
    build_emerging_finding,
    classify_taxonomy,
    cluster_non_cve_signals,
    prepare_discovery_signals,
    referenced_discovery_records,
    related_cves,
)
from packages.scoring.engine import PublicationThresholds
from packages.storage.object_store import LocalImmutableObjectStore


def test_taxonomy_classifies_ai_supply_chain_and_malicious_packages() -> None:
    taxonomy = classify_taxonomy(
        "Malicious npm package targets AI agents",
        "Researchers found a poisoned open-source package in a software supply chain.",
    )

    assert taxonomy.category == "malicious_package"
    assert {"ai", "open_source", "pre_cve", "supply_chain"}.issubset(taxonomy.tags)


def test_taxonomy_preserves_critical_exploitation_primitives() -> None:
    taxonomy = classify_taxonomy(
        "Wormable pre-auth RCE in edge VPN is actively exploited",
        "Researchers report widespread exploitation and authentication bypass.",
    )

    assert {
        "active_exploitation",
        "authentication_bypass",
        "edge_device",
        "mass_exploitation",
        "remote_code_execution",
    }.issubset(taxonomy.tags)


def test_pre_cve_sources_become_cited_emerging_finding(tmp_path: Path) -> None:
    generated_at = datetime(2026, 7, 24, 13, tzinfo=UTC)
    signals = [
        DiscoverySignal(
            source_id="x-researchers",
            title="Malicious npm package targets AI agents",
            url="https://x.com/researcher/status/123",
            summary=(
                "A newly observed malicious npm package installs an infostealer in AI "
                "agent development environments."
            ),
            published_at=datetime(2026, 7, 24, 11, tzinfo=UTC),
            identifiers=(),
            source_handle="researcher",
        ),
        DiscoverySignal(
            source_id="brave-web",
            title="AI agent developers warned about malicious npm package",
            url="https://security.example/research/npm-ai-agent-package",
            summary=(
                "Independent research describes the malicious npm package and related "
                "infostealer activity before any CVE assignment."
            ),
            published_at=datetime(2026, 7, 24, 12, tzinfo=UTC),
            identifiers=(),
        ),
    ]
    prepared = prepare_discovery_signals(
        signals,
        generated_at=generated_at,
        object_store=LocalImmutableObjectStore(tmp_path / "objects"),
    )
    clusters = cluster_non_cve_signals(prepared)
    finding = build_emerging_finding(
        clusters[0],
        generated_at=generated_at,
        thresholds=PublicationThresholds(),
    )
    evidence, artifacts = referenced_discovery_records([finding], prepared)

    validate_payload("finding.schema.json", finding)
    assert len(clusters[0]) == 2
    assert finding["category"] == "malicious_package"
    assert {"ai", "supply_chain", "pre_cve"}.issubset(finding["tags"])
    assert finding["publication_class"] == "watch"
    assert finding["emergence_stage"] == "credible_emerging"
    assert finding["mappings"] == []
    assert {item["source_type"] for item in finding["source_evidence"]} == {
        "website",
        "x_post",
    }
    assert all(item["verification_status"] == "verified" for item in finding["claims"])
    assert len(evidence) == 2
    assert len(artifacts) == 2


def test_unrelated_live_topics_do_not_form_one_confident_cluster(
    tmp_path: Path,
) -> None:
    generated_at = datetime(2026, 7, 24, 15, tzinfo=UTC)
    signals = [
        DiscoverySignal(
            source_id="brave-web",
            title="AI Prompts - HackTricks",
            url="https://hacktricks.example/ai-prompts",
            summary="Observed prompt injection patterns and defensive guidance.",
            published_at=generated_at,
            identifiers=(),
        ),
        DiscoverySignal(
            source_id="x-researchers",
            title="RubyGems cryptojacking campaign with 113 malicious packages",
            url="https://x.com/researcher/status/456",
            summary="A malicious package campaign delivered XMRig miners.",
            published_at=generated_at,
            identifiers=(),
            source_handle="researcher",
        ),
        DiscoverySignal(
            source_id="brave-web",
            title="Chaos ransomware hides C2 inside Chrome using WebRTC",
            url="https://news.example/chaos-ransomware",
            summary="Chaos ransomware used a browser-mediated command channel.",
            published_at=generated_at,
            identifiers=(),
        ),
    ]
    prepared = prepare_discovery_signals(
        signals,
        generated_at=generated_at,
        object_store=LocalImmutableObjectStore(tmp_path / "objects"),
    )

    clusters = cluster_non_cve_signals(prepared)

    assert len(clusters) == 3
    assert all(len(cluster) == 1 for cluster in clusters)


def test_repeat_collection_creates_distinct_immutable_artifact_events(
    tmp_path: Path,
) -> None:
    generated_at = datetime(2026, 7, 24, 15, tzinfo=UTC)
    signal = DiscoverySignal(
        source_id="brave-web",
        title="Chaos ransomware hides C2 inside Chrome using WebRTC",
        url="https://news.example/chaos-ransomware",
        summary="Chaos ransomware used a browser-mediated command channel.",
        published_at=generated_at,
        identifiers=(),
    )
    object_store = LocalImmutableObjectStore(tmp_path / "objects")

    first = prepare_discovery_signals(
        [signal],
        generated_at=generated_at,
        object_store=object_store,
    )[0]
    second = prepare_discovery_signals(
        [signal],
        generated_at=generated_at + timedelta(minutes=5),
        object_store=object_store,
    )[0]

    assert first.artifact["content_hash"] == second.artifact["content_hash"]
    assert first.artifact["artifact_id"] != second.artifact["artifact_id"]
    assert first.artifact["retrieved_at"] != second.artifact["retrieved_at"]


def test_duplicate_smartconsole_coverage_clusters_across_sites(
    tmp_path: Path,
) -> None:
    generated_at = datetime(2026, 7, 24, 15, tzinfo=UTC)
    signals = [
        DiscoverySignal(
            source_id="brave-web",
            title=("Check Point Patches Exploited SmartConsole Flaw Allowing Full Admin Access"),
            url="https://thehackernews.example/check-point-smartconsole",
            summary=(
                "Check Point SmartConsole is actively exploited in the wild and "
                "permits admin access."
            ),
            published_at=generated_at,
            identifiers=(),
        ),
        DiscoverySignal(
            source_id="brave-web",
            title=(
                "Critical Check Point SmartConsole Flaw Exploited in the Wild to "
                "Bypass Authentication"
            ),
            url="https://gbhackers.example/check-point-smartconsole",
            summary="Check Point SmartConsole exploitation bypasses authentication.",
            published_at=generated_at + timedelta(hours=1),
            identifiers=(),
        ),
    ]
    prepared = prepare_discovery_signals(
        signals,
        generated_at=generated_at + timedelta(hours=2),
        object_store=LocalImmutableObjectStore(tmp_path / "objects"),
    )

    clusters = cluster_non_cve_signals(prepared)

    assert len(clusters) == 1
    assert len(clusters[0]) == 2


def test_source_native_cluster_links_to_exactly_one_known_cve(
    tmp_path: Path,
) -> None:
    generated_at = datetime(2026, 7, 24, 15, tzinfo=UTC)
    signals = [
        DiscoverySignal(
            source_id="x-researchers",
            title="Check Point SmartConsole zero-day exploited in attacks",
            url="https://x.com/researcher/status/789",
            summary="SmartConsole authentication bypass was exploited in the wild.",
            published_at=generated_at,
            identifiers=(),
            source_handle="researcher",
        ),
        DiscoverySignal(
            source_id="brave-web",
            title="Check Point SmartConsole flaw tracked as CVE-2026-16232",
            url="https://vendor.example/cve-2026-16232",
            summary="CVE-2026-16232 is an exploited SmartConsole authentication bypass.",
            published_at=generated_at,
            identifiers=("CVE-2026-16232",),
        ),
    ]
    prepared = prepare_discovery_signals(
        signals,
        generated_at=generated_at + timedelta(hours=1),
        object_store=LocalImmutableObjectStore(tmp_path / "objects"),
    )
    cluster = cluster_non_cve_signals(prepared)[0]

    assert related_cves(cluster, prepared) == ("CVE-2026-16232",)
