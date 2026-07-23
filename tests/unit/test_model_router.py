from decimal import Decimal
from pathlib import Path

import pytest

from packages.model_router.router import ModelRouteDenied, ModelRouter, RouteRequest


def test_chief_is_reserved_for_material_coordination() -> None:
    router = ModelRouter.from_path(Path("config/models.yaml"))
    normal = router.select(
        RouteRequest(
            task="coordinate",
            run_spend=Decimal("0"),
            cluster_spend=Decimal("0"),
            daily_spend=Decimal("0"),
            priority_score=60,
        )
    )
    chief = router.select(
        RouteRequest(
            task="coordinate",
            run_spend=Decimal("0"),
            cluster_spend=Decimal("0"),
            daily_spend=Decimal("0"),
            priority_score=90,
            flash_candidate=True,
        )
    )
    assert normal.route_name == "balanced_analyst"
    assert chief.route_name == "chief_coordinator"
    assert chief.model == "openai/gpt-5.6-sol"
    assert chief.harness == "codex"
    assert chief.thinking == "ultra"


def test_hard_budget_fails_closed_and_flash_reserve_is_protected() -> None:
    router = ModelRouter.from_path(Path("config/models.yaml"))
    request = RouteRequest(
        task="analyze",
        run_spend=Decimal("1"),
        cluster_spend=Decimal("1"),
        daily_spend=Decimal("105"),
    )
    with pytest.raises(ModelRouteDenied, match="reserved"):
        router.select(request)
