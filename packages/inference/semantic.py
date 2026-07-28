from __future__ import annotations

import json
import math
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx
import yaml

from packages.discovery.clients import candidate_cves
from packages.discovery.emerging import PreparedSignal

OLLAMA_EMBED_ENDPOINT = "http://127.0.0.1:11434/api/embed"
OLLAMA_PROVIDER = "ollama"
MAX_VECTOR_DIMENSIONS = 4096
MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,79}$")


class SemanticShadowError(RuntimeError):
    """A bounded local-inference failure with no source content in the message."""


@dataclass(frozen=True, slots=True)
class SemanticShadowSettings:
    enabled: bool
    mode: str
    model: str
    timeout_seconds: float
    maximum_signals_per_run: int
    maximum_text_characters: int
    similarity_threshold: float
    maximum_candidate_pairs: int
    maximum_response_bytes: int


@dataclass(frozen=True, slots=True)
class EmbeddingBatch:
    vectors: tuple[tuple[float, ...], ...]
    requests: int
    input_tokens: int
    duration_ms: int


class EmbeddingClient(Protocol):
    async def embed(self, texts: tuple[str, ...]) -> EmbeddingBatch: ...


@dataclass(frozen=True, slots=True)
class SemanticShadowResult:
    status: str
    model: str
    similarity_threshold: float
    discovered_signal_count: int
    evaluated_signal_count: int
    truncated_signal_count: int
    deterministic_pair_count: int
    candidate_pair_count: int
    overlap_pair_count: int
    semantic_only_pair_count: int
    deterministic_only_pair_count: int
    requests: int
    input_tokens: int
    duration_ms: int
    vector_dimensions: int | None
    failure_reason: str | None
    candidate_pairs: tuple[dict[str, Any], ...] = ()

    def as_report(self) -> dict[str, Any]:
        return {
            "mode": "shadow",
            "status": self.status,
            "provider": OLLAMA_PROVIDER,
            "model": self.model,
            "similarity_threshold": self.similarity_threshold,
            "discovered_signal_count": self.discovered_signal_count,
            "evaluated_signal_count": self.evaluated_signal_count,
            "truncated_signal_count": self.truncated_signal_count,
            "deterministic_pair_count": self.deterministic_pair_count,
            "candidate_pair_count": self.candidate_pair_count,
            "overlap_pair_count": self.overlap_pair_count,
            "semantic_only_pair_count": self.semantic_only_pair_count,
            "deterministic_only_pair_count": self.deterministic_only_pair_count,
            "requests": self.requests,
            "input_tokens": self.input_tokens,
            "duration_ms": self.duration_ms,
            "vector_dimensions": self.vector_dimensions,
            "failure_reason": self.failure_reason,
            "candidate_pairs": list(self.candidate_pairs),
            "publication_authority": False,
        }


class OllamaEmbeddingClient:
    """Strict loopback-only Ollama client for numeric embedding output."""

    def __init__(
        self,
        settings: SemanticShadowSettings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport

    async def embed(self, texts: tuple[str, ...]) -> EmbeddingBatch:
        if not texts:
            raise ValueError("embedding input cannot be empty")
        if len(texts) > self._settings.maximum_signals_per_run:
            raise ValueError("embedding input exceeds the configured signal limit")
        if any(not text or len(text) > self._settings.maximum_text_characters for text in texts):
            raise ValueError("embedding text violates configured bounds")
        started = time.monotonic()
        try:
            async with (
                httpx.AsyncClient(
                    transport=self._transport,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=self._settings.timeout_seconds,
                ) as client,
                client.stream(
                    "POST",
                    OLLAMA_EMBED_ENDPOINT,
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self._settings.model,
                        "input": list(texts),
                        "truncate": True,
                    },
                ) as response,
            ):
                if response.status_code != 200:
                    raise SemanticShadowError("local_inference_unavailable")
                content_length = response.headers.get("content-length")
                if (
                    content_length is not None
                    and int(content_length) > self._settings.maximum_response_bytes
                ):
                    raise SemanticShadowError("response_too_large")
                payload = bytearray()
                async for chunk in response.aiter_bytes():
                    payload.extend(chunk)
                    if len(payload) > self._settings.maximum_response_bytes:
                        raise SemanticShadowError("response_too_large")
        except SemanticShadowError:
            raise
        except (httpx.HTTPError, OSError, ValueError) as exc:
            raise SemanticShadowError("local_inference_unavailable") from exc
        try:
            value = json.loads(bytes(payload))
        except (UnicodeDecodeError, ValueError) as exc:
            raise SemanticShadowError("invalid_response") from exc
        if not isinstance(value, dict) or value.get("model") != self._settings.model:
            raise SemanticShadowError("invalid_response")
        raw_vectors = value.get("embeddings")
        if not isinstance(raw_vectors, list) or len(raw_vectors) != len(texts):
            raise SemanticShadowError("invalid_response")
        vectors: list[tuple[float, ...]] = []
        dimensions: int | None = None
        for raw_vector in raw_vectors:
            if not isinstance(raw_vector, list):
                raise SemanticShadowError("invalid_response")
            vector = tuple(_finite_float(item) for item in raw_vector)
            if (
                not vector
                or len(vector) > MAX_VECTOR_DIMENSIONS
                or math.isclose(sum(item * item for item in vector), 0.0)
            ):
                raise SemanticShadowError("invalid_response")
            dimensions = dimensions or len(vector)
            if len(vector) != dimensions:
                raise SemanticShadowError("invalid_response")
            vectors.append(vector)
        input_tokens = value.get("prompt_eval_count", 0)
        if not isinstance(input_tokens, int) or isinstance(input_tokens, bool) or input_tokens < 0:
            raise SemanticShadowError("invalid_response")
        return EmbeddingBatch(
            vectors=tuple(vectors),
            requests=1,
            input_tokens=input_tokens,
            duration_ms=max(0, round((time.monotonic() - started) * 1000)),
        )


class SemanticShadowEvaluator:
    """Compare embedding candidates to deterministic clusters without mutating them."""

    def __init__(
        self,
        settings: SemanticShadowSettings,
        client: EmbeddingClient,
    ) -> None:
        self.settings = settings
        self._client = client

    async def evaluate(
        self,
        signals: tuple[PreparedSignal, ...],
        deterministic_clusters: tuple[tuple[PreparedSignal, ...], ...],
    ) -> SemanticShadowResult:
        eligible = sorted(
            (item for item in signals if not candidate_cves((item.signal,))),
            key=lambda item: (
                item.signal.published_at.isoformat()
                if item.signal.published_at is not None
                else "",
                item.signal.title,
                item.signal.url,
            ),
        )
        discovered_count = len(eligible)
        evaluated = tuple(eligible[: self.settings.maximum_signals_per_run])
        truncated_count = discovered_count - len(evaluated)
        deterministic_pairs = _deterministic_pairs(
            deterministic_clusters,
            {str(item.evidence["evidence_id"]) for item in evaluated},
        )
        if len(evaluated) < 2:
            return _empty_result(
                self.settings,
                discovered_count=discovered_count,
                evaluated_count=len(evaluated),
                truncated_count=truncated_count,
                deterministic_pair_count=len(deterministic_pairs),
                failure_reason="insufficient_signals",
            )
        try:
            batch = await self._client.embed(
                tuple(
                    _embedding_text(
                        item,
                        maximum=self.settings.maximum_text_characters,
                    )
                    for item in evaluated
                )
            )
            if len(batch.vectors) != len(evaluated):
                raise SemanticShadowError("invalid_response")
            candidates: list[tuple[float, str, str]] = []
            for left_index, left in enumerate(evaluated):
                for right_index in range(left_index + 1, len(evaluated)):
                    right = evaluated[right_index]
                    if not _compatible_categories(left, right):
                        continue
                    similarity = _cosine(
                        batch.vectors[left_index],
                        batch.vectors[right_index],
                    )
                    if similarity >= self.settings.similarity_threshold:
                        left_id, right_id = sorted(
                            (
                                str(left.evidence["evidence_id"]),
                                str(right.evidence["evidence_id"]),
                            )
                        )
                        candidates.append((similarity, left_id, right_id))
        except SemanticShadowError as exc:
            return _empty_result(
                self.settings,
                discovered_count=discovered_count,
                evaluated_count=len(evaluated),
                truncated_count=truncated_count,
                deterministic_pair_count=len(deterministic_pairs),
                failure_reason=str(exc),
                status="degraded",
                requests=1,
            )
        candidates.sort(key=lambda item: (-item[0], item[1], item[2]))
        semantic_pairs = {(left, right) for _, left, right in candidates}
        overlap = semantic_pairs.intersection(deterministic_pairs)
        stored_pairs = tuple(
            {
                "left_evidence_id": left,
                "right_evidence_id": right,
                "similarity": round(similarity, 6),
                "deterministic_match": (left, right) in deterministic_pairs,
            }
            for similarity, left, right in candidates[: self.settings.maximum_candidate_pairs]
        )
        return SemanticShadowResult(
            status="completed",
            model=self.settings.model,
            similarity_threshold=self.settings.similarity_threshold,
            discovered_signal_count=discovered_count,
            evaluated_signal_count=len(evaluated),
            truncated_signal_count=truncated_count,
            deterministic_pair_count=len(deterministic_pairs),
            candidate_pair_count=len(semantic_pairs),
            overlap_pair_count=len(overlap),
            semantic_only_pair_count=len(semantic_pairs - deterministic_pairs),
            deterministic_only_pair_count=len(deterministic_pairs - semantic_pairs),
            requests=batch.requests,
            input_tokens=batch.input_tokens,
            duration_ms=batch.duration_ms,
            vector_dimensions=len(batch.vectors[0]),
            failure_reason=None,
            candidate_pairs=stored_pairs,
        )

    def degraded_result(
        self,
        signals: tuple[PreparedSignal, ...],
        *,
        failure_reason: str = "shadow_evaluation_failed",
    ) -> SemanticShadowResult:
        discovered_count = sum(not candidate_cves((item.signal,)) for item in signals)
        evaluated_count = min(
            discovered_count,
            self.settings.maximum_signals_per_run,
        )
        return _empty_result(
            self.settings,
            discovered_count=discovered_count,
            evaluated_count=evaluated_count,
            truncated_count=discovered_count - evaluated_count,
            deterministic_pair_count=0,
            failure_reason=failure_reason,
            status="degraded",
        )


def load_semantic_shadow_settings(path: Path) -> SemanticShadowSettings:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"version", "semantic_clustering"}:
        raise ValueError("local inference configuration has invalid top-level fields")
    if value["version"] != 1:
        raise ValueError("unsupported local inference configuration version")
    raw = value["semantic_clustering"]
    if not isinstance(raw, dict):
        raise ValueError("semantic_clustering must be an object")
    expected = {
        "enabled",
        "mode",
        "provider",
        "model",
        "timeout_seconds",
        "maximum_signals_per_run",
        "maximum_text_characters",
        "similarity_threshold",
        "maximum_candidate_pairs",
        "maximum_response_bytes",
    }
    if set(raw) != expected:
        raise ValueError("semantic_clustering has invalid configuration fields")
    if raw["provider"] != OLLAMA_PROVIDER:
        raise ValueError("only the loopback Ollama provider is supported")
    if raw["mode"] != "shadow":
        raise ValueError("local semantic clustering must remain in shadow mode")
    enabled = _strict_bool(raw["enabled"], "enabled")
    model = str(raw["model"])
    if MODEL_PATTERN.fullmatch(model) is None:
        raise ValueError("invalid Ollama model name")
    timeout_seconds = _bounded_number(raw["timeout_seconds"], 1, 30, "timeout_seconds")
    maximum_signals = _bounded_integer(
        raw["maximum_signals_per_run"],
        2,
        64,
        "maximum_signals_per_run",
    )
    maximum_text = _bounded_integer(
        raw["maximum_text_characters"],
        200,
        2000,
        "maximum_text_characters",
    )
    threshold = _bounded_number(
        raw["similarity_threshold"],
        0.5,
        0.99,
        "similarity_threshold",
    )
    maximum_pairs = _bounded_integer(
        raw["maximum_candidate_pairs"],
        1,
        100,
        "maximum_candidate_pairs",
    )
    maximum_response = _bounded_integer(
        raw["maximum_response_bytes"],
        100_000,
        8_000_000,
        "maximum_response_bytes",
    )
    return SemanticShadowSettings(
        enabled=enabled,
        mode="shadow",
        model=model,
        timeout_seconds=timeout_seconds,
        maximum_signals_per_run=maximum_signals,
        maximum_text_characters=maximum_text,
        similarity_threshold=threshold,
        maximum_candidate_pairs=maximum_pairs,
        maximum_response_bytes=maximum_response,
    )


def build_semantic_shadow_evaluator(path: Path) -> SemanticShadowEvaluator | None:
    settings = load_semantic_shadow_settings(path)
    if not settings.enabled:
        return None
    return SemanticShadowEvaluator(settings, OllamaEmbeddingClient(settings))


def _embedding_text(signal: PreparedSignal, *, maximum: int) -> str:
    source = "\n".join(
        part
        for part in (
            signal.signal.title,
            signal.signal.summary,
            signal.signal.rationale or "",
        )
        if part
    )
    cleaned = " ".join(source.replace("\x00", " ").split())
    prefix = "clustering: "
    return prefix + cleaned[: maximum - len(prefix)]


def _compatible_categories(left: PreparedSignal, right: PreparedSignal) -> bool:
    categories = {left.taxonomy.category, right.taxonomy.category}
    return len(categories) == 1 or categories == {
        "active_exploitation",
        "vulnerability",
    }


def _deterministic_pairs(
    clusters: tuple[tuple[PreparedSignal, ...], ...],
    eligible_ids: set[str],
) -> set[tuple[str, str]]:
    result: set[tuple[str, str]] = set()
    for cluster in clusters:
        ids = sorted(
            str(item.evidence["evidence_id"])
            for item in cluster
            if str(item.evidence["evidence_id"]) in eligible_ids
        )
        for left_index, left in enumerate(ids):
            for right in ids[left_index + 1 :]:
                result.add((left, right))
    return result


def _cosine(left: tuple[float, ...], right: tuple[float, ...]) -> float:
    if len(left) != len(right) or not left:
        raise SemanticShadowError("invalid_response")
    left_norm = math.sqrt(sum(item * item for item in left))
    right_norm = math.sqrt(sum(item * item for item in right))
    if math.isclose(left_norm, 0.0) or math.isclose(right_norm, 0.0):
        raise SemanticShadowError("invalid_response")
    return sum(a * b for a, b in zip(left, right, strict=True)) / (left_norm * right_norm)


def _finite_float(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise SemanticShadowError("invalid_response")
    result = float(value)
    if not math.isfinite(result) or abs(result) > 1_000_000:
        raise SemanticShadowError("invalid_response")
    return result


def _empty_result(
    settings: SemanticShadowSettings,
    *,
    discovered_count: int,
    evaluated_count: int,
    truncated_count: int,
    deterministic_pair_count: int,
    failure_reason: str,
    status: str = "skipped",
    requests: int = 0,
) -> SemanticShadowResult:
    return SemanticShadowResult(
        status=status,
        model=settings.model,
        similarity_threshold=settings.similarity_threshold,
        discovered_signal_count=discovered_count,
        evaluated_signal_count=evaluated_count,
        truncated_signal_count=truncated_count,
        deterministic_pair_count=deterministic_pair_count,
        candidate_pair_count=0,
        overlap_pair_count=0,
        semantic_only_pair_count=0,
        deterministic_only_pair_count=deterministic_pair_count,
        requests=requests,
        input_tokens=0,
        duration_ms=0,
        vector_dimensions=None,
        failure_reason=failure_reason,
    )


def _strict_bool(value: object, name: str) -> bool:
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _bounded_number(value: object, minimum: float, maximum: float, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise ValueError(f"{name} must be numeric")
    result = float(value)
    if not minimum <= result <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return result


def _bounded_integer(value: object, minimum: int, maximum: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value
