from __future__ import annotations

import asyncio
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml


class AgentBudgetDenied(RuntimeError):
    """Raised before dispatch when a reservation would cross a configured hard limit."""


@dataclass(frozen=True, slots=True)
class AgentBudgetLimits:
    daily_hard: Decimal
    flash_reserve: Decimal
    per_run: Decimal
    per_cluster: Decimal


class AgentBudget:
    """Concurrency-safe, conservative reservation ledger for one workflow run."""

    def __init__(self, limits: AgentBudgetLimits, *, daily_spend: Decimal = Decimal("0")) -> None:
        values = (
            limits.daily_hard,
            limits.flash_reserve,
            limits.per_run,
            limits.per_cluster,
            daily_spend,
        )
        if any(value < 0 for value in values):
            raise ValueError("agent budget values cannot be negative")
        if limits.flash_reserve > limits.daily_hard:
            raise ValueError("Flash reserve cannot exceed the daily hard limit")
        self.limits = limits
        self.daily_spend = daily_spend
        self._run_reserved = Decimal("0")
        self._cluster_reserved: dict[str, Decimal] = {}
        self._lock = asyncio.Lock()

    @classmethod
    def from_path(
        cls,
        path: Path,
        *,
        daily_spend: Decimal = Decimal("0"),
    ) -> AgentBudget:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict) or not isinstance(value.get("budgets"), dict):
            raise ValueError("model budget configuration must contain budgets")
        budgets: dict[str, Any] = value["budgets"]
        return cls(
            AgentBudgetLimits(
                daily_hard=Decimal(str(budgets["daily_currency_hard_limit"])),
                flash_reserve=Decimal(str(budgets["flash_reserve_currency"])),
                per_run=Decimal(str(budgets["per_run_currency_limit"])),
                per_cluster=Decimal(str(budgets["per_cluster_currency_limit"])),
            ),
            daily_spend=daily_spend,
        )

    async def reserve(
        self,
        *,
        finding_id: str,
        maximum_currency: Decimal,
        flash_candidate: bool,
    ) -> None:
        if maximum_currency <= 0:
            raise AgentBudgetDenied("agent route has no positive maximum currency reservation")
        async with self._lock:
            cluster_reserved = self._cluster_reserved.get(finding_id, Decimal("0"))
            if cluster_reserved + maximum_currency > self.limits.per_cluster:
                raise AgentBudgetDenied("cluster model budget would be exceeded")
            if self._run_reserved + maximum_currency > self.limits.per_run:
                raise AgentBudgetDenied("run model budget would be exceeded")
            projected_daily = self.daily_spend + self._run_reserved + maximum_currency
            if projected_daily > self.limits.daily_hard:
                raise AgentBudgetDenied("daily hard model budget would be exceeded")
            non_flash_limit = self.limits.daily_hard - self.limits.flash_reserve
            if not flash_candidate and projected_daily > non_flash_limit:
                raise AgentBudgetDenied("remaining daily model budget is reserved for Flash")
            self._run_reserved += maximum_currency
            self._cluster_reserved[finding_id] = cluster_reserved + maximum_currency

    def snapshot(self) -> dict[str, str]:
        return {
            "daily_spend": str(self.daily_spend),
            "run_reserved": str(self._run_reserved),
            "daily_hard": str(self.limits.daily_hard),
            "flash_reserve": str(self.limits.flash_reserve),
            "per_run": str(self.limits.per_run),
            "per_cluster": str(self.limits.per_cluster),
        }
