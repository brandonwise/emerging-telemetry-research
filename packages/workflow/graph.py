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
    for node in nodes:
        if not node.node_id or any(dependency not in by_id for dependency in node.depends_on):
            raise ValueError(f"graph node {node.node_id!r} has an invalid dependency")
        if node.node_id in node.depends_on:
            raise ValueError(f"graph node {node.node_id!r} depends on itself")

    outputs: dict[str, GraphOutput] = {}
    pending = set(by_id)
    layers: list[list[str]] = []
    while pending:
        ready = sorted(
            node_id
            for node_id in pending
            if set(by_id[node_id].depends_on).issubset(outputs)
        )
        if not ready:
            raise ValueError("workflow graph contains a cycle")
        snapshot = dict(outputs)
        with ThreadPoolExecutor(
            max_workers=min(maximum_parallel_nodes, len(ready))
        ) as executor:
            futures = {
                node_id: executor.submit(by_id[node_id].handler, snapshot)
                for node_id in ready
            }
            for node_id in ready:
                value = futures[node_id].result()
                if not isinstance(value, dict):
                    raise TypeError(f"graph node {node_id!r} returned a non-object")
                outputs[node_id] = value
        pending.difference_update(ready)
        layers.append(ready)

    manifest = {
        "schema_version": "1.0",
        "layers": layers,
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
            {"from": dependency, "to": node.node_id}
            for node in nodes
            for dependency in node.depends_on
        ],
    }
    return GraphExecution(outputs=outputs, manifest=manifest)
