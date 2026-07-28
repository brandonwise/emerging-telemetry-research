import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from packages.discovery.clients import DiscoverySignal
from packages.discovery.emerging import (
    PreparedSignal,
    cluster_non_cve_signals,
    prepare_discovery_signals,
)
from packages.inference.semantic import (
    EmbeddingBatch,
    OllamaEmbeddingClient,
    SemanticShadowError,
    SemanticShadowEvaluator,
    SemanticShadowSettings,
    load_semantic_shadow_settings,
)
from packages.storage.object_store import LocalImmutableObjectStore


def _settings(**overrides: object) -> SemanticShadowSettings:
    values: dict[str, object] = {
        "enabled": True,
        "mode": "shadow",
        "model": "nomic-embed-text:latest",
        "timeout_seconds": 10.0,
        "maximum_signals_per_run": 64,
        "maximum_text_characters": 1200,
        "similarity_threshold": 0.9,
        "maximum_candidate_pairs": 20,
        "maximum_response_bytes": 4_000_000,
    }
    values.update(overrides)
    return SemanticShadowSettings(**values)  # type: ignore[arg-type]


def _signals(tmp_path: Path) -> tuple[PreparedSignal, ...]:
    generated_at = datetime(2026, 7, 28, 12, tzinfo=UTC)
    signals = [
        DiscoverySignal(
            source_id="brave-web",
            title="Check Point SmartConsole flaw exploited in the wild",
            url="https://security.example/smartconsole",
            summary="Attackers are exploiting an authentication bypass.",
            published_at=generated_at,
            identifiers=(),
        ),
        DiscoverySignal(
            source_id="x-researchers",
            title="Exploited Check Point SmartConsole authentication bypass",
            url="https://x.com/researcher/status/1",
            summary="SmartConsole attacks are active.",
            published_at=generated_at + timedelta(minutes=1),
            identifiers=(),
            source_handle="researcher",
        ),
        DiscoverySignal(
            source_id="brave-web",
            title="Poisoned library steals developer credentials",
            url="https://security.example/poisoned-library",
            summary="A malicious package targets developer environments.",
            published_at=generated_at + timedelta(minutes=2),
            identifiers=(),
        ),
        DiscoverySignal(
            source_id="x-researchers",
            title="Typosquatted dependency deploys an infostealer",
            url="https://x.com/researcher/status/2",
            summary="Researchers found a malicious npm package.",
            published_at=generated_at + timedelta(minutes=3),
            identifiers=(),
            source_handle="researcher",
        ),
    ]
    return prepare_discovery_signals(
        signals,
        generated_at=generated_at + timedelta(hours=1),
        object_store=LocalImmutableObjectStore(tmp_path / "objects"),
    )


def test_local_inference_config_is_shadow_only() -> None:
    settings = load_semantic_shadow_settings(Path("config/embeddings.yaml"))

    assert settings.enabled is True
    assert settings.mode == "shadow"
    assert settings.model == "nomic-embed-text:latest"
    assert settings.maximum_signals_per_run == 64


@pytest.mark.asyncio
async def test_ollama_client_uses_fixed_loopback_endpoint_and_validates_vectors() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "http://127.0.0.1:11434/api/embed"
        assert json.loads(request.content) == {
            "model": "nomic-embed-text:latest",
            "input": ["clustering: first", "clustering: second"],
            "truncate": True,
        }
        return httpx.Response(
            200,
            json={
                "model": "nomic-embed-text:latest",
                "embeddings": [[1.0, 0.0], [0.0, 1.0]],
                "prompt_eval_count": 9,
            },
        )

    result = await OllamaEmbeddingClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    ).embed(("clustering: first", "clustering: second"))

    assert result.vectors == ((1.0, 0.0), (0.0, 1.0))
    assert result.requests == 1
    assert result.input_tokens == 9


@pytest.mark.asyncio
async def test_ollama_client_rejects_model_substitution() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        del request
        return httpx.Response(
            200,
            json={
                "model": "unexpected-model",
                "embeddings": [[1.0, 0.0], [0.0, 1.0]],
            },
        )

    client = OllamaEmbeddingClient(
        _settings(),
        transport=httpx.MockTransport(handler),
    )

    with pytest.raises(SemanticShadowError, match="invalid_response"):
        await client.embed(("clustering: first", "clustering: second"))


@pytest.mark.asyncio
async def test_semantic_candidates_do_not_mutate_deterministic_clusters(
    tmp_path: Path,
) -> None:
    prepared = _signals(tmp_path)
    deterministic = cluster_non_cve_signals(prepared)

    class FakeEmbeddings:
        async def embed(self, texts: tuple[str, ...]) -> EmbeddingBatch:
            assert len(texts) == 4
            return EmbeddingBatch(
                vectors=(
                    (1.0, 0.0),
                    (0.99, 0.01),
                    (0.0, 1.0),
                    (0.01, 0.99),
                ),
                requests=1,
                input_tokens=80,
                duration_ms=7,
            )

    result = await SemanticShadowEvaluator(
        _settings(),
        FakeEmbeddings(),
    ).evaluate(prepared, deterministic)

    assert sorted(len(cluster) for cluster in deterministic) == [1, 1, 2]
    assert result.status == "completed"
    assert result.deterministic_pair_count == 1
    assert result.candidate_pair_count == 2
    assert result.overlap_pair_count == 1
    assert result.semantic_only_pair_count == 1
    assert len(result.candidate_pairs) == 2
    assert any(not item["deterministic_match"] for item in result.candidate_pairs)


@pytest.mark.asyncio
async def test_local_inference_failure_degrades_shadow_only(tmp_path: Path) -> None:
    prepared = _signals(tmp_path)
    deterministic = cluster_non_cve_signals(prepared)

    class FailingEmbeddings:
        async def embed(self, texts: tuple[str, ...]) -> EmbeddingBatch:
            del texts
            raise SemanticShadowError("local_inference_unavailable")

    result = await SemanticShadowEvaluator(
        _settings(),
        FailingEmbeddings(),
    ).evaluate(prepared, deterministic)

    assert result.status == "degraded"
    assert result.failure_reason == "local_inference_unavailable"
    assert result.requests == 1
    assert sorted(len(cluster) for cluster in deterministic) == [1, 1, 2]
