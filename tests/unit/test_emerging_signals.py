from datetime import UTC, datetime
from pathlib import Path

from packages.contracts.validation import validate_payload
from packages.discovery.clients import DiscoverySignal
from packages.discovery.emerging import (
    build_emerging_finding,
    classify_taxonomy,
    cluster_non_cve_signals,
    prepare_discovery_signals,
    referenced_discovery_records,
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
