from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml


class ModelRouteDenied(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RouteRequest:
    task: str
    run_spend: Decimal
    cluster_spend: Decimal
    daily_spend: Decimal
    priority_score: float = 0
    flash_candidate: bool = False
    specialist_disagreement: bool = False
    material_contradiction: bool = False


@dataclass(frozen=True, slots=True)
class ModelRoute:
    route_name: str
    provider: str | None
    model: str | None
    harness: str | None
    thinking: str | None
    max_input_tokens: int | None
    max_output_tokens: int | None
    tools: tuple[str, ...]


class ModelRouter:
    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config

    @classmethod
    def from_path(cls, path: Path) -> ModelRouter:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError("model configuration must be an object")
        return cls(value)

    def select(self, request: RouteRequest) -> ModelRoute:
        budgets = self.config["budgets"]
        hard_daily = Decimal(str(budgets["daily_currency_hard_limit"]))
        run_limit = Decimal(str(budgets["per_run_currency_limit"]))
        cluster_limit = Decimal(str(budgets["per_cluster_currency_limit"]))
        flash_reserve = Decimal(str(budgets["flash_reserve_currency"]))
        if request.cluster_spend >= cluster_limit:
            raise ModelRouteDenied("cluster model budget exhausted")
        if request.run_spend >= run_limit:
            raise ModelRouteDenied("run model budget exhausted")
        if request.daily_spend >= hard_daily:
            raise ModelRouteDenied("daily hard budget exhausted")
        if request.daily_spend >= hard_daily - flash_reserve and not request.flash_candidate:
            raise ModelRouteDenied("remaining daily budget is reserved for Flash candidates")

        route_name = _route_name(request)
        route = self.config["routes"][route_name]
        if route_name == "deterministic":
            return ModelRoute(
                route_name=route_name,
                provider=None,
                model=None,
                harness=None,
                thinking=None,
                max_input_tokens=None,
                max_output_tokens=None,
                tools=(),
            )
        provider = route["provider_preferences"][0]
        return ModelRoute(
            route_name=route_name,
            provider=str(provider["provider"]),
            model=str(provider["model"]),
            harness=str(provider["harness"]) if provider.get("harness") else None,
            thinking=str(provider["thinking"]) if provider.get("thinking") else None,
            max_input_tokens=int(route["max_input_tokens"]),
            max_output_tokens=int(route["max_output_tokens"]),
            tools=tuple(str(item) for item in route.get("tools", [])),
        )


def _route_name(request: RouteRequest) -> str:
    if request.task in {
        "fetch",
        "hash",
        "deduplicate",
        "normalize_identifiers",
        "compute_features",
        "score",
        "validate_schema",
        "render",
    }:
        return "deterministic"
    if request.task in {"extract", "classify_content"}:
        return "economical_extractor"
    if (
        request.priority_score >= 78
        or request.flash_candidate
        or request.specialist_disagreement
        or request.material_contradiction
    ) and request.task == "coordinate":
        return "chief_coordinator"
    return "balanced_analyst"
