from decimal import Decimal
from pathlib import Path

import pytest

from packages.model_router.budget import AgentBudget, AgentBudgetDenied


@pytest.mark.asyncio
async def test_budget_reservations_enforce_cluster_and_run_limits() -> None:
    budget = AgentBudget.from_path(Path("config/models.yaml"))

    for _ in range(7):
        await budget.reserve(
            finding_id="fd_one",
            maximum_currency=Decimal("0.40"),
            flash_candidate=True,
        )
    with pytest.raises(AgentBudgetDenied, match="cluster"):
        await budget.reserve(
            finding_id="fd_one",
            maximum_currency=Decimal("0.40"),
            flash_candidate=True,
        )


@pytest.mark.asyncio
async def test_budget_preserves_daily_flash_reserve() -> None:
    budget = AgentBudget.from_path(
        Path("config/models.yaml"),
        daily_spend=Decimal("99.80"),
    )

    with pytest.raises(AgentBudgetDenied, match="reserved for Flash"):
        await budget.reserve(
            finding_id="fd_daily",
            maximum_currency=Decimal("0.40"),
            flash_candidate=False,
        )
    await budget.reserve(
        finding_id="fd_flash",
        maximum_currency=Decimal("0.80"),
        flash_candidate=True,
    )
    assert budget.snapshot()["run_reserved"] == "0.80"
