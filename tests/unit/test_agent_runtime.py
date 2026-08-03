import json
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path

import httpx
import pytest

from packages.agents.planning import build_shadow_agent_plans
from packages.agents.runtime import (
    AgentInvocation,
    AgentProviderResult,
    FixtureAgentProvider,
    OpenAICompatibleAgentProvider,
    RoutedAgentProvider,
    _maximum_currency_reservation,
    evidence_packet_from_finding,
    execute_agent_reviews,
)
from packages.evaluation.agent_harness import run_agent_evaluation
from packages.model_router.router import ModelRouter


def _finding() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "finding_id": "fd_agent_runtime",
        "cluster_id": "cl_agent_runtime",
        "title": "Emerging package compromise",
        "why_now": "Two fresh sources reported the same package compromise.",
        "category": "malicious_package",
        "emergence_stage": "credible_emerging",
        "publication_class": "watch",
        "priority_score": 72.0,
        "confidence": {"level": "medium", "probability": 0.7, "rationale": "Two sources."},
        "unknown": ["Affected versions remain unknown."],
        "contradictions": [],
        "claims": [
            {
                "claim_id": "claim_one",
                "text": "A researcher reported malicious package behavior.",
                "certainty": "reported",
                "evidence_ids": ["ev_agent_one"],
                "verification_status": "verified",
            },
            {
                "claim_id": "claim_two",
                "text": "A second source reported credential theft.",
                "certainty": "reported",
                "evidence_ids": ["ev_agent_two"],
                "verification_status": "verified",
            },
        ],
        "source_evidence": [
            {
                "evidence_id": "ev_agent_one",
                "source_id": "reddit-security",
                "source_type": "reddit_post",
                "title": "Package report",
                "url": "https://www.reddit.com/r/netsec/comments/example/",
                "published_at": "2026-07-30T12:00:00Z",
                "retrieved_at": "2026-07-30T12:05:00Z",
                "excerpt": "A researcher reported malicious package behavior.",
                "source_handle": "researcher",
            },
            {
                "evidence_id": "ev_agent_two",
                "source_id": "web-security-research",
                "source_type": "website",
                "title": "Independent analysis",
                "url": "https://security.example/package-analysis",
                "published_at": "2026-07-30T12:10:00Z",
                "retrieved_at": "2026-07-30T12:15:00Z",
                "excerpt": "A second source reported credential theft.",
                "source_handle": None,
            },
        ],
    }


def test_evidence_packet_from_finding_contains_only_bounded_evidence() -> None:
    generated_at = datetime(2026, 7, 30, 13, tzinfo=UTC)
    packet = evidence_packet_from_finding(
        _finding(),
        run_id="run_agent_runtime",
        generated_at=generated_at,
    )
    assert [item["source_role"] for item in packet["evidence"]] == [
        "researcher_observation",
        "precursor",
    ]
    assert {item["evidence_id"] for item in packet["evidence"]} == {
        "ev_agent_one",
        "ev_agent_two",
    }
    assert "raw_content" not in str(packet)


@pytest.mark.asyncio
async def test_agent_runtime_executes_parallel_dag_and_applies_active_review() -> None:
    generated_at = datetime(2026, 7, 30, 13, tzinfo=UTC)
    finding = _finding()
    plans = build_shadow_agent_plans(
        [finding],
        run_id="run_agent_runtime",
        generated_at=generated_at,
        router=ModelRouter.from_path(Path("config/models.yaml")),
    )
    invocations: list[AgentInvocation] = []
    fixture = FixtureAgentProvider()

    class RecordingProvider:
        async def invoke(self, invocation: AgentInvocation) -> AgentProviderResult:
            invocations.append(invocation)
            return await fixture.invoke(invocation)

    result = await execute_agent_reviews(
        findings=[finding],
        plans=plans,
        run_id="run_agent_runtime",
        generated_at=generated_at,
        provider=RecordingProvider(),
        mode="active",
    )

    assert result.reviews[0]["status"] == "completed"
    assert result.reviews[0]["dispatch_executed"] is True
    assert result.reviews[0]["report_mutation_executed"] is True
    assert result.reviews[0]["publication_authority"] is False
    assert len(result.assessments) == 5
    assert len(result.usage) == 5
    verifier = next(item for item in invocations if item.role == "citation_verifier")
    coordinator = next(item for item in invocations if item.role == "coordinator")
    assert {item["agent_role"] for item in verifier.prior_assessments} == {
        "specialist",
        "impact",
        "skeptic",
    }
    assert len(coordinator.prior_assessments) == 4
    assert finding["skeptic_summary"] == (
        "No uncited external facts were used; source independence remains material."
    )


@pytest.mark.asyncio
async def test_openai_compatible_provider_falls_back_without_json_schema() -> None:
    requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        requests.append(payload)
        if len(requests) == 1:
            return httpx.Response(400, json={"error": "response_format unsupported"})
        return httpx.Response(
            200,
            json={
                "model": "portable-model",
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "judgment": "Bounded result.",
                                    "claims": [],
                                    "uncertainties": [],
                                    "contradictions": [],
                                    "recommended_disposition": "watch",
                                    "requested_followups": [],
                                }
                            )
                        }
                    }
                ],
                "usage": {"prompt_tokens": 12, "completion_tokens": 8},
            },
        )

    generated_at = datetime(2026, 7, 30, 13, tzinfo=UTC)
    invocation = AgentInvocation(
        run_id="run_portable",
        finding_id="fd_agent_runtime",
        role="skeptic",
        route={"model": "portable-model", "recommended_disposition": "watch"},
        packet=evidence_packet_from_finding(
            _finding(),
            run_id="run_portable",
            generated_at=generated_at,
        ),
        prior_assessments=(),
        created_at="2026-07-30T13:00:00Z",
    )
    provider = OpenAICompatibleAgentProvider(
        api_key="test-key",
        base_url="https://agents.example/v1",
        model="portable-model",
        transport=httpx.MockTransport(handler),
        input_price_per_million=1.0,
        output_price_per_million=2.0,
    )
    result = await provider.invoke(invocation)

    assert len(requests) == 2
    assert "response_format" in requests[0]
    assert "response_format" not in requests[1]
    assert result.assessment["judgment"] == "Bounded result."
    assert result.input_tokens == 12
    assert result.output_tokens == 8
    assert result.estimated_currency == 0.000028


@pytest.mark.asyncio
async def test_routed_provider_retries_then_falls_back() -> None:
    generated_at = datetime(2026, 7, 30, 13, tzinfo=UTC)
    finding = _finding()
    route = build_shadow_agent_plans(
        [finding],
        run_id="run_routed",
        generated_at=generated_at,
        router=ModelRouter.from_path(Path("config/models.yaml")),
    )[0]["routes"][0]

    class FailingProvider:
        def __init__(self) -> None:
            self.calls = 0

        async def invoke(self, invocation: AgentInvocation) -> AgentProviderResult:
            self.calls += 1
            raise RuntimeError(f"primary unavailable for {invocation.role}")

    primary = FailingProvider()
    provider = RoutedAgentProvider(
        providers={"codex": primary, "openclaw": FixtureAgentProvider()},
    )
    result = await provider.invoke(
        AgentInvocation(
            run_id="run_routed",
            finding_id="fd_agent_runtime",
            role=str(route["role"]),
            route=route,
            packet=evidence_packet_from_finding(
                finding,
                run_id="run_routed",
                generated_at=generated_at,
            ),
            prior_assessments=(),
            created_at="2026-07-30T13:00:00Z",
        )
    )

    assert primary.calls == 2
    assert result.provider == "fixture"


def test_route_reservation_covers_every_retry_and_fallback() -> None:
    assert _maximum_currency_reservation(
        {
            "maximum_currency_per_call": 0.12,
            "provider_preferences": [{"provider": "one"}, {"provider": "two"}],
            "retries": 1,
        }
    ) == Decimal("0.48")


def test_route_reservation_rejects_unbounded_provider_preferences() -> None:
    with pytest.raises(ValueError, match="provider preferences"):
        _maximum_currency_reservation(
            {
                "maximum_currency_per_call": 0.12,
                "provider_preferences": [{"provider": str(index)} for index in range(6)],
                "retries": 1,
            }
        )


@pytest.mark.asyncio
async def test_agent_evaluation_persists_returned_assessments(tmp_path: Path) -> None:
    result = await run_agent_evaluation(
        fixtures_root=Path("tests/fixtures/vertical_slice"),
        output_root=tmp_path,
        provider=FixtureAgentProvider(),
        adapter_name="fixture",
        repeats=1,
        case="flash",
    )

    assert result["passed"] is True
    assert result["metrics"]["total_tokens"] == 0
    assert result["metrics"]["factual_claim_citation_coverage"] == 1.0
    assert result["metrics"]["disposition_agreement_by_role"]["coordinator"] == 1.0
    assert result["gates"]["all_assessments_include_claims"] is True
    assert result["gates"]["all_factual_claims_cite_evidence"] is True
    assert result["cases"][0]["role_dispositions"]["coordinator"] == "flash"
    artifact_path = tmp_path / result["cases"][0]["assessment_artifact"]
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert len(artifact["review"]["assessments"]) == 5
    assert len(artifact["usage"]) == 5
