import pytest

from packages.workflow.graph import GraphNode, execute_graph


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
