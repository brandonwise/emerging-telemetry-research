from datetime import UTC, datetime
from pathlib import Path

from packages.agents.planning import build_shadow_agent_plans
from packages.model_router.router import ModelRouter


def test_shadow_agent_plan_uses_parallel_review_graph_and_chief_route() -> None:
    plans = build_shadow_agent_plans(
        [
            {
                "finding_id": "fd_test_flash",
                "priority_score": 90.0,
                "publication_class": "flash",
            }
        ],
        run_id="run_test",
        generated_at=datetime(2026, 7, 29, 13, 30, tzinfo=UTC),
        router=ModelRouter.from_path(Path("config/models.yaml")),
    )

    plan = plans[0]
    assert plan["graph"]["layers"] == [
        ["impact", "skeptic", "specialist"],
        ["citation_verifier"],
        ["coordinator"],
    ]
    coordinator = next(
        route for route in plan["routes"] if route["role"] == "coordinator"
    )
    assert coordinator["route_name"] == "chief_coordinator"
    assert coordinator["model"] == "openai/gpt-5.6-sol"
    assert plan["raw_source_content_included"] is False
    assert plan["dispatch_executed"] is False
    assert plan["publication_authority"] is False


def test_daily_shadow_plan_keeps_coordinator_on_balanced_route() -> None:
    plans = build_shadow_agent_plans(
        [
            {
                "finding_id": "fd_test_daily",
                "priority_score": 55.0,
                "publication_class": "daily",
            }
        ],
        run_id="run_test",
        generated_at=datetime(2026, 7, 29, 13, 30, tzinfo=UTC),
        router=ModelRouter.from_path(Path("config/models.yaml")),
    )

    coordinator = next(
        route for route in plans[0]["routes"] if route["role"] == "coordinator"
    )
    assert coordinator["route_name"] == "balanced_analyst"
    assert [item["harness"] for item in coordinator["provider_preferences"]] == [
        "codex",
        "openclaw",
    ]
    assert coordinator["retries"] == 1
