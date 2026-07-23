from packages.lineage.graph import LineageEdge, independent_source_count, validate_lineage


def test_ten_syndicated_posts_count_as_one_origin() -> None:
    evidence_ids = tuple(f"ev_{index}" for index in range(11))
    edges = (
        LineageEdge("ev_0", None, "original"),
        *(
            LineageEdge(f"ev_{index}", "ev_0", "syndicates")
            for index in range(1, 11)
        ),
    )
    validate_lineage(evidence_ids, edges)
    assert independent_source_count(evidence_ids, edges) == 1
