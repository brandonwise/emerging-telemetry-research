from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any

from packages.common.canonical import canonical_json_bytes, sha256_hex

GraphOutput = dict[str, Any]
GraphHandler = Callable[[dict[str, GraphOutput]], GraphOutput]


@dataclass(frozen=True, slots=True)
class GraphNode:
    node_id: str
    depends_on: tuple[str, ...]
    handler: GraphHandler


@dataclass(frozen=True, slots=True)
class GraphExecution:
    outputs: dict[str, GraphOutput]
    manifest: dict[str, Any]


@dataclass(frozen=True, slots=True)
class GraphPlan:
    layers: tuple[tuple[str, ...], ...]
    edges: tuple[tuple[str, str], ...]

    def to_contract(self) -> dict[str, Any]:
        return {
            "layers": [list(layer) for layer in self.layers],
            "edges": [
                {"from": source, "to": target}
                for source, target in self.edges
            ],
        }


def plan_graph(dependencies: dict[str, tuple[str, ...]]) -> GraphPlan:
    """Validate and layer an explicit DAG without executing any node."""
    for node_id, node_dependencies in dependencies.items():
        if (
            not node_id
            or node_id in node_dependencies
            or any(dependency not in dependencies for dependency in node_dependencies)
        ):
            raise ValueError(f"graph node {node_id!r} has an invalid dependency")

    completed: set[str] = set()
    pending = set(dependencies)
    layers: list[tuple[str, ...]] = []
    while pending:
        ready = tuple(
            sorted(
                node_id
                for node_id in pending
                if set(dependencies[node_id]).issubset(completed)
            )
        )
        if not ready:
            raise ValueError("workflow graph contains a cycle")
        layers.append(ready)
        completed.update(ready)
        pending.difference_update(ready)

    edges = tuple(
        (dependency, node_id)
        for node_id in dependencies
        for dependency in dependencies[node_id]
    )
    return GraphPlan(layers=tuple(layers), edges=edges)


def execute_graph(
    nodes: tuple[GraphNode, ...],
    *,
    maximum_parallel_nodes: int = 4,
) -> GraphExecution:
    """Execute an explicit DAG, running each ready layer in parallel."""
    if maximum_parallel_nodes < 1:
        raise ValueError("maximum_parallel_nodes must be positive")
    by_id = {node.node_id: node for node in nodes}
    if len(by_id) != len(nodes):
        raise ValueError("graph node IDs must be unique")
    plan = plan_graph({node.node_id: node.depends_on for node in nodes})

    outputs: dict[str, GraphOutput] = {}
    for layer in plan.layers:
        snapshot = dict(outputs)
        with ThreadPoolExecutor(
            max_workers=min(maximum_parallel_nodes, len(layer))
        ) as executor:
            futures = {
                node_id: executor.submit(by_id[node_id].handler, snapshot)
                for node_id in layer
            }
            for node_id in layer:
                value = futures[node_id].result()
                if not isinstance(value, dict):
                    raise TypeError(f"graph node {node_id!r} returned a non-object")
                outputs[node_id] = value

    manifest = {
        "schema_version": "1.0",
        "layers": [list(layer) for layer in plan.layers],
        "nodes": [
            {
                "node_id": node.node_id,
                "depends_on": list(node.depends_on),
                "output_sha256": sha256_hex(canonical_json_bytes(outputs[node.node_id])),
                "status": "completed",
            }
            for node in nodes
        ],
        "edges": [
            {"from": source, "to": target}
            for source, target in plan.edges
        ],
    }
    return GraphExecution(outputs=outputs, manifest=manifest)
