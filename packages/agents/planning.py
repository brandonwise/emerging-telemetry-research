from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from typing import Any

from packages.common.canonical import format_timestamp, stable_id
from packages.model_router.router import ModelRoute, ModelRouter, RouteRequest
from packages.workflow.graph import plan_graph

ROLE_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "specialist": (),
    "impact": (),
    "skeptic": (),
    "citation_verifier": ("specialist", "impact", "skeptic"),
    "coordinator": ("citation_verifier",),
}


def build_shadow_agent_plans(
    findings: list[dict[str, Any]],
    *,
    run_id: str,
    generated_at: datetime,
    router: ModelRouter,
) -> list[dict[str, Any]]:
    """Plan the configured review graph without dispatching agents or models."""
    graph = plan_graph(ROLE_DEPENDENCIES).to_contract()
    plans: list[dict[str, Any]] = []
    for finding in findings:
        finding_id = str(finding["finding_id"])
        priority_score = float(finding["priority_score"])
        publication_class = str(finding["publication_class"])
        routes = [
            _route_contract(
                role,
                router.select(
                    RouteRequest(
                        task="coordinate" if role == "coordinator" else "analyze",
                        run_spend=Decimal("0"),
                        cluster_spend=Decimal("0"),
                        daily_spend=Decimal("0"),
                        priority_score=priority_score,
                        flash_candidate=publication_class == "flash",
                    )
                ),
            )
            for layer in graph["layers"]
            for role in layer
        ]
        plans.append(
            {
                "mode": "shadow",
                "status": "planned",
                "plan_id": stable_id("ap", run_id, finding_id, "shadow-v1"),
                "run_id": run_id,
                "finding_id": finding_id,
                "created_at": format_timestamp(generated_at),
                "graph": graph,
                "routes": routes,
                "input_contract": "evidence-packet.schema.json",
                "output_contract": "assessment.schema.json",
                "raw_source_content_included": False,
                "dispatch_executed": False,
                "publication_authority": False,
            }
        )
    return plans


def _route_contract(role: str, route: ModelRoute) -> dict[str, Any]:
    return {
        "role": role,
        "route_name": route.route_name,
        "provider": route.provider,
        "model": route.model,
        "harness": route.harness,
        "thinking": route.thinking,
        "max_input_tokens": route.max_input_tokens,
        "max_output_tokens": route.max_output_tokens,
        "tools": list(route.tools),
    }
