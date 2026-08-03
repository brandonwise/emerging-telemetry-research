from pathlib import Path

import pytest

from packages.workflow.checkpoints import CheckpointConflict, SQLiteCheckpointStore
from packages.workflow.graph import GraphNode, execute_graph, plan_graph
from packages.workflow.loops import LoopDecision, execute_bounded_loop


def test_graph_executes_ready_nodes_as_a_parallel_layer() -> None:
    execution = execute_graph(
        (
            GraphNode("root", (), lambda _outputs: {"value": 2}),
            GraphNode(
                "left",
                ("root",),
                lambda outputs: {"value": outputs["root"]["value"] + 3},
            ),
            GraphNode(
                "right",
                ("root",),
                lambda outputs: {"value": outputs["root"]["value"] * 4},
            ),
            GraphNode(
                "join",
                ("left", "right"),
                lambda outputs: {
                    "value": outputs["left"]["value"] + outputs["right"]["value"]
                },
            ),
        )
    )

    assert execution.outputs["join"]["value"] == 13
    assert execution.manifest["layers"] == [["root"], ["left", "right"], ["join"]]


def test_graph_rejects_cycles() -> None:
    with pytest.raises(ValueError, match="cycle"):
        execute_graph(
            (
                GraphNode("a", ("b",), lambda _outputs: {}),
                GraphNode("b", ("a",), lambda _outputs: {}),
            )
        )


def test_graph_plan_exposes_layers_without_executing_handlers() -> None:
    plan = plan_graph(
        {
            "specialist": (),
            "impact": (),
            "skeptic": (),
            "verifier": ("specialist", "impact", "skeptic"),
            "coordinator": ("verifier",),
        }
    )

    assert plan.to_contract() == {
        "layers": [
            ["impact", "skeptic", "specialist"],
            ["verifier"],
            ["coordinator"],
        ],
        "edges": [
            {"from": "specialist", "to": "verifier"},
            {"from": "impact", "to": "verifier"},
            {"from": "skeptic", "to": "verifier"},
            {"from": "verifier", "to": "coordinator"},
        ],
    }


def test_graph_retries_checkpoints_and_resumes(tmp_path: Path) -> None:
    root = tmp_path
    calls = {"root": 0, "join": 0}

    def flaky(_outputs: dict[str, dict[str, object]]) -> dict[str, object]:
        calls["root"] += 1
        if calls["root"] == 1:
            raise RuntimeError("transient")
        return {"value": 4}

    def join(outputs: dict[str, dict[str, object]]) -> dict[str, object]:
        calls["join"] += 1
        return {"value": int(outputs["root"]["value"]) + 1}

    nodes = (
        GraphNode("root", (), flaky, maximum_attempts=2),
        GraphNode("join", ("root",), join),
    )
    store = SQLiteCheckpointStore(root / "checkpoints.db")
    first = execute_graph(nodes, workflow_id="workflow-test", checkpoint_store=store)
    resumed = execute_graph(nodes, workflow_id="workflow-test", checkpoint_store=store)

    assert first.outputs["join"] == {"value": 5}
    assert first.manifest["nodes"][0]["attempts"] == 2
    assert calls == {"root": 2, "join": 1}
    assert {item["status"] for item in resumed.manifest["nodes"]} == {"resumed"}


def test_checkpoint_rejects_node_revision_drift(tmp_path: Path) -> None:
    store = SQLiteCheckpointStore(tmp_path / "checkpoints.db")
    execute_graph(
        (GraphNode("root", (), lambda _outputs: {"value": 1}),),
        workflow_id="workflow-test",
        checkpoint_store=store,
    )

    with pytest.raises(CheckpointConflict, match="input changed"):
        execute_graph(
            (GraphNode("root", (), lambda _outputs: {"value": 1}, revision="2"),),
            workflow_id="workflow-test",
            checkpoint_store=store,
        )


def test_bounded_loop_completes_and_detects_stalls() -> None:
    completed = execute_bounded_loop(
        {"count": 0},
        lambda _iteration, state: LoopDecision(
            {"count": int(state["count"]) + 1},
            int(state["count"]) + 1 == 3,
            "advance",
        ),
        maximum_iterations=5,
    )

    assert completed.state == {"count": 3}
    assert completed.manifest["status"] == "completed"
    with pytest.raises(RuntimeError, match="repeated"):
        execute_bounded_loop(
            {"count": 0},
            lambda _iteration, state: LoopDecision(state, False, "no progress"),
            maximum_iterations=3,
        )


def test_bounded_loop_reports_limit_reached() -> None:
    result = execute_bounded_loop(
        {"count": 0},
        lambda _iteration, state: LoopDecision(
            {"count": int(state["count"]) + 1},
            False,
            "advance",
        ),
        maximum_iterations=2,
    )

    assert result.manifest["status"] == "limit_reached"
    assert result.state == {"count": 2}
