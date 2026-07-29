import json
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from packages.common.canonical import canonical_json_bytes
from packages.delivery.discord import build_discord_delivery_plan
from packages.delivery.local import build_local_delivery_plan
from packages.discovery.clients import (
    DiscoverySignal,
    DiscoveryUsage,
    XSearchResult,
)
from packages.inference.semantic import (
    EmbeddingBatch,
    SemanticShadowEvaluator,
    load_semantic_shadow_settings,
)
from packages.pipeline.frozen import run_frozen_fixture
from packages.pipeline.live import (
    LiveRunSettings,
    _discovery_baselines,
    _existing_morning_result,
    _prioritized_candidates,
    _select_report_findings,
    run_live_radar,
)
from packages.storage.object_store import LocalImmutableObjectStore
from packages.storage.repository import MemoryRepository


def test_discovery_baseline_uses_first_current_signal_per_cve() -> None:
    generated_at = datetime(2026, 7, 24, 12, tzinfo=UTC)
    signals = [
        DiscoverySignal(
            source_id="brave-web",
            title="Current report",
            url="https://example.com/one",
            summary="CVE-2026-12345",
            published_at=datetime(2026, 7, 24, 10, tzinfo=UTC),
            identifiers=("CVE-2026-12345",),
        ),
        DiscoverySignal(
            source_id="x-researchers",
            title="Earlier post",
            url="https://x.com/example/status/1",
            summary="CVE-2026-12345",
            published_at=datetime(2026, 7, 24, 9, tzinfo=UTC),
            identifiers=("CVE-2026-12345",),
            source_handle="example",
        ),
    ]
    assert _discovery_baselines(signals, generated_at) == {
        "CVE-2026-12345": datetime(2026, 7, 24, 9, tzinfo=UTC)
    }


def test_critical_exploitation_language_prioritizes_authoritative_corroboration() -> None:
    signals = [
        *[
            DiscoverySignal(
                source_id="brave-web",
                title=f"Routine update {index}",
                url=f"https://example.com/routine-{index}",
                summary="A vendor published CVE-2026-11111 with no exploitation reported.",
                published_at=datetime(2026, 7, 24, 10, tzinfo=UTC),
                identifiers=("CVE-2026-11111",),
            )
            for index in range(4)
        ],
        DiscoverySignal(
            source_id="brave-web",
            title="Pre-auth RCE is actively exploited on edge devices",
            url="https://example.com/critical",
            summary=(
                "CVE-2026-22222 is an unauthenticated remote code execution issue "
                "under active exploitation in gateway appliances."
            ),
            published_at=datetime(2026, 7, 24, 11, tzinfo=UTC),
            identifiers=("CVE-2026-22222",),
        ),
    ]

    prioritized = _prioritized_candidates(
        signals,
        cisa_artifact=None,
        minimum_date=date(2026, 7, 23),
        maximum=1,
    )

    assert prioritized == ("CVE-2026-22222",)


def test_report_reserves_slots_for_qualifying_pre_cve_findings() -> None:
    cve_findings = [
        {
            "finding_id": f"fd_cve_{index}",
            "publication_class": "watch",
            "priority_score": 90.0 - index,
        }
        for index in range(5)
    ]
    emerging_findings = [
        {
            "finding_id": "fd_emerging_one",
            "publication_class": "daily",
            "priority_score": 55.0,
        },
        {
            "finding_id": "fd_emerging_two",
            "publication_class": "daily",
            "priority_score": 50.0,
        },
    ]

    selected = _select_report_findings(
        cve_findings=cve_findings,
        emerging_findings=emerging_findings,
        minimum_class="daily",
        maximum_findings=5,
        minimum_emerging_findings=2,
    )

    assert {finding["finding_id"] for finding in selected}.issuperset(
        {"fd_emerging_one", "fd_emerging_two"}
    )
    assert len(selected) == 5


def test_existing_morning_run_is_reused_for_same_local_day(tmp_path: Path) -> None:
    run_root = tmp_path / "run_existing"
    frozen = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        run_root,
    )
    plan = build_discord_delivery_plan(
        frozen.report,
        html_path=frozen.rendered.path,
        channel_id="1476897068885872814",
    )
    plan_path = run_root / f"{frozen.report['report_id']}.delivery.json"
    plan_path.write_bytes(canonical_json_bytes(plan) + b"\n")

    existing = _existing_morning_result(
        LiveRunSettings(
            output_root=tmp_path,
            discord_channel_id="1476897068885872814",
        ),
        datetime(2026, 7, 22, 18, tzinfo=UTC),
    )

    assert existing is not None
    assert existing.run_id == "run_existing"
    assert existing.report["report_id"] == frozen.report["report_id"]
    assert existing.summary == plan["summary"]
    assert existing.delivery_plan_path == plan_path


def test_existing_morning_run_is_not_reused_on_next_local_day(tmp_path: Path) -> None:
    run_root = tmp_path / "run_existing"
    frozen = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        run_root,
    )
    plan = build_discord_delivery_plan(
        frozen.report,
        html_path=frozen.rendered.path,
        channel_id="1476897068885872814",
    )
    (run_root / f"{frozen.report['report_id']}.delivery.json").write_text(
        json.dumps(plan),
        encoding="utf-8",
    )

    existing = _existing_morning_result(
        LiveRunSettings(
            output_root=tmp_path,
            discord_channel_id="1476897068885872814",
        ),
        datetime(2026, 7, 23, 18, tzinfo=UTC),
    )

    assert existing is None


def test_existing_portable_morning_run_is_reused_without_discord(tmp_path: Path) -> None:
    run_root = tmp_path / "run_existing"
    frozen = run_frozen_fixture(
        Path("tests/fixtures/vertical_slice/early-manifest.json"),
        run_root,
    )
    plan = build_local_delivery_plan(
        frozen.report,
        html_path=frozen.rendered.path,
    )
    (run_root / f"{frozen.report['report_id']}.delivery.json").write_bytes(
        canonical_json_bytes(plan) + b"\n"
    )

    existing = _existing_morning_result(
        LiveRunSettings(output_root=tmp_path),
        datetime(2026, 7, 22, 18, tzinfo=UTC),
    )

    assert existing is not None
    assert existing.delivery_plan["destination"] == "file:local"


@pytest.mark.asyncio
async def test_live_pipeline_publishes_pre_cve_source_native_signal(
    tmp_path: Path,
) -> None:
    generated_at = datetime(2026, 7, 24, 13, tzinfo=UTC)
    brave_signal = DiscoverySignal(
        source_id="brave-web",
        title="AI agent developers warned about malicious npm package",
        url="https://security.example/research/npm-ai-agent-package",
        summary=(
            "Independent research describes a malicious npm package and infostealer "
            "activity before any CVE assignment."
        ),
        published_at=datetime(2026, 7, 24, 12, tzinfo=UTC),
        identifiers=(),
    )
    x_signal = DiscoverySignal(
        source_id="x-researchers",
        title="Malicious npm package targets AI agents",
        url="https://x.com/researcher/status/123",
        summary=(
            "A newly observed malicious npm package installs an infostealer in AI agent "
            "development environments."
        ),
        published_at=datetime(2026, 7, 24, 11, tzinfo=UTC),
        identifiers=(),
        source_handle="researcher",
    )

    class FakeBrave:
        async def search(
            self,
            query: str,
            *,
            freshness: str,
            count: int,
        ) -> tuple[DiscoverySignal, ...]:
            del query, freshness, count
            return (brave_signal,)

    class FakeX:
        async def search(
            self,
            *,
            from_date: date,
            to_date: date,
            allowed_handles: tuple[str, ...],
        ) -> XSearchResult:
            del from_date, to_date, allowed_handles
            return XSearchResult(
                signals=(x_signal,),
                usage=DiscoveryUsage(
                    provider="xai",
                    model="fixture",
                    requests=1,
                    input_tokens=10,
                    output_tokens=5,
                    estimated_currency=0.01,
                    tool_calls=1,
                ),
            )

    class FailingOfficial:
        async def fetch(self, spec: object) -> None:
            del spec
            raise RuntimeError("fixture source unavailable")

    class FakeEmbeddings:
        async def embed(self, texts: tuple[str, ...]) -> EmbeddingBatch:
            assert len(texts) == 2
            return EmbeddingBatch(
                vectors=((1.0, 0.0), (0.99, 0.01)),
                requests=1,
                input_tokens=20,
                duration_ms=5,
            )

    repository = MemoryRepository()
    result = await run_live_radar(
        LiveRunSettings(
            output_root=tmp_path / "reports",
            edition="afternoon_delta",
        ),
        brave_client=FakeBrave(),  # type: ignore[arg-type]
        x_search_client=FakeX(),  # type: ignore[arg-type]
        official_client=FailingOfficial(),  # type: ignore[arg-type]
        object_store=LocalImmutableObjectStore(tmp_path / "objects"),
        repository=repository,
        semantic_evaluator=SemanticShadowEvaluator(
            load_semantic_shadow_settings(Path("config/embeddings.yaml")),
            FakeEmbeddings(),
        ),
        now=generated_at,
    )

    assert result.candidate_cves == ()
    assert result.emerging_signal_count == 1
    assert result.report["findings"][0]["category"] == "malicious_package"
    assert result.report["findings"][0]["mappings"] == []
    assert {item["source_type"] for item in result.report["findings"][0]["source_evidence"]} == {
        "website",
        "x_post",
    }
    brave_usage = next(item for item in result.report["usage"] if item["provider"] == "brave")
    assert brave_usage["requests"] == 5
    assert brave_usage["estimated_currency"] == 0.025
    assert result.semantic_shadow is not None
    assert result.semantic_shadow["status"] == "completed"
    assert result.semantic_shadow["candidate_pair_count"] == 1
    assert result.semantic_shadow["publication_authority"] is False
    ollama_usage = next(item for item in result.report["usage"] if item["provider"] == "ollama")
    assert ollama_usage["estimated_currency"] == 0
    assert ollama_usage["input_tokens"] == 20
    assert len(repository.evidence) == 2
    assert len(repository.artifacts) == 2
    assert result.report["agent_shadow_plans"][0]["dispatch_executed"] is False
    assert result.report["agent_shadow_plans"][0]["publication_authority"] is False
    assert result.report["agent_shadow_plans"][0]["graph"]["layers"] == [
        ["impact", "skeptic", "specialist"],
        ["citation_verifier"],
        ["coordinator"],
    ]
    routing_usage = next(
        item
        for item in result.report["usage"]
        if item["stage"] == "agent_routing_shadow"
    )
    assert routing_usage["requests"] == 0
    assert routing_usage["estimated_currency"] == 0
