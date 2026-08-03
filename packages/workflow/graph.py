from __future__ import annotations

from collections.abc import Callable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Protocol

from packages.common.canonical import canonical_json_bytes, sha256_hex

GraphOutput = dict[str, Any]
GraphHandler = Callable[[dict[str, GraphOutput]], GraphOutput]


class CheckpointStore(Protocol):
    def load(
        self, workflow_id: str, node_id: str, input_hash: str
    ) -> tuple[GraphOutput, int] | None: ...

    def save(
        self,
        workflow_id: str,
        node_id: str,
        input_hash: str,
        output: GraphOutput,
        attempts: int,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class GraphNode:
    node_id: str
    depends_on: tuple[str, ...]
    handler: GraphHandler
    revision: str = "1"
    maximum_attempts: int = 1


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
    workflow_id: str | None = None,
    checkpoint_store: CheckpointStore | None = None,
) -> GraphExecution:
    """Execute an explicit DAG, running each ready layer in parallel."""
    if maximum_parallel_nodes < 1:
        raise ValueError("maximum_parallel_nodes must be positive")
    if (workflow_id is None) != (checkpoint_store is None):
        raise ValueError("workflow_id and checkpoint_store must be configured together")
    by_id = {node.node_id: node for node in nodes}
    if len(by_id) != len(nodes):
        raise ValueError("graph node IDs must be unique")
    plan = plan_graph({node.node_id: node.depends_on for node in nodes})
    for node in nodes:
        if not 1 <= node.maximum_attempts <= 5:
            raise ValueError("graph node maximum_attempts must be between one and five")

    outputs: dict[str, GraphOutput] = {}
    attempts_by_node: dict[str, int] = {}
    resumed: set[str] = set()
    for layer in plan.layers:
        snapshot = dict(outputs)
        pending: list[str] = []
        input_hashes: dict[str, str] = {}
        for node_id in layer:
            node = by_id[node_id]
            input_hash = _input_hash(node, snapshot)
            input_hashes[node_id] = input_hash
            checkpoint = (
                checkpoint_store.load(str(workflow_id), node_id, input_hash)
                if checkpoint_store is not None
                else None
            )
            if checkpoint is None:
                pending.append(node_id)
                continue
            outputs[node_id], attempts_by_node[node_id] = checkpoint
            resumed.add(node_id)
        if not pending:
            continue
        with ThreadPoolExecutor(
            max_workers=min(maximum_parallel_nodes, len(pending))
        ) as executor:
            futures = {
                node_id: executor.submit(_run_node, by_id[node_id], snapshot)
                for node_id in pending
            }
            failures: list[tuple[str, Exception]] = []
            for node_id in pending:
                try:
                    value, attempts = futures[node_id].result()
                except Exception as exc:
                    failures.append((node_id, exc))
                    continue
                if not isinstance(value, dict):
                    raise TypeError(f"graph node {node_id!r} returned a non-object")
                outputs[node_id] = value
                attempts_by_node[node_id] = attempts
                if checkpoint_store is not None:
                    checkpoint_store.save(
                        str(workflow_id),
                        node_id,
                        input_hashes[node_id],
                        value,
                        attempts,
                    )
            if failures:
                node_id, error = failures[0]
                raise RuntimeError(f"graph node {node_id!r} failed after retries") from error

    manifest = {
        "schema_version": "1.0",
        "layers": [list(layer) for layer in plan.layers],
        "nodes": [
            {
                "node_id": node.node_id,
                "depends_on": list(node.depends_on),
                "output_sha256": sha256_hex(canonical_json_bytes(outputs[node.node_id])),
                "status": "resumed" if node.node_id in resumed else "completed",
                "attempts": attempts_by_node[node.node_id],
                "revision": node.revision,
            }
            for node in nodes
        ],
        "edges": [
            {"from": source, "to": target}
            for source, target in plan.edges
        ],
    }
    return GraphExecution(outputs=outputs, manifest=manifest)


def _input_hash(node: GraphNode, outputs: Mapping[str, GraphOutput]) -> str:
    dependencies = {dependency: outputs[dependency] for dependency in node.depends_on}
    return sha256_hex(
        canonical_json_bytes(
            {
                "node_id": node.node_id,
                "revision": node.revision,
                "dependencies": dependencies,
            }
        )
    )


def _run_node(
    node: GraphNode,
    outputs: dict[str, GraphOutput],
) -> tuple[GraphOutput, int]:
    for attempt in range(1, node.maximum_attempts + 1):
        try:
            return node.handler(outputs), attempt
        except Exception:
            if attempt == node.maximum_attempts:
                raise
    raise RuntimeError("unreachable graph retry state")
