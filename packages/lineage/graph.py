from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LineageEdge:
    child_evidence_id: str
    parent_evidence_id: str | None
    relationship: str
    confidence: float = 1.0

    def to_contract(self) -> dict[str, object]:
        return {
            "child_evidence_id": self.child_evidence_id,
            "parent_evidence_id": self.parent_evidence_id,
            "relationship": self.relationship,
            "confidence": self.confidence,
        }


DEPENDENT_RELATIONSHIPS = {"quotes", "reposts", "syndicates", "links_to", "derives_from"}


def origin_for(evidence_id: str, edges: tuple[LineageEdge, ...]) -> str:
    parents = {
        edge.child_evidence_id: edge.parent_evidence_id
        for edge in edges
        if edge.relationship in DEPENDENT_RELATIONSHIPS and edge.parent_evidence_id
    }
    current = evidence_id
    visited: set[str] = set()
    while current in parents:
        if current in visited:
            raise ValueError("lineage cycle detected")
        visited.add(current)
        parent = parents[current]
        assert parent is not None
        current = parent
    return current


def independent_source_count(
    evidence_ids: tuple[str, ...],
    edges: tuple[LineageEdge, ...],
) -> int:
    return len({origin_for(evidence_id, edges) for evidence_id in evidence_ids})


def validate_lineage(evidence_ids: tuple[str, ...], edges: tuple[LineageEdge, ...]) -> None:
    known = set(evidence_ids)
    children: set[str] = set()
    for edge in edges:
        if edge.child_evidence_id not in known:
            raise ValueError("lineage child does not exist")
        if edge.parent_evidence_id is not None and edge.parent_evidence_id not in known:
            raise ValueError("lineage parent does not exist")
        if edge.child_evidence_id in children:
            raise ValueError("evidence has multiple lineage declarations")
        if not 0 <= edge.confidence <= 1:
            raise ValueError("lineage confidence outside [0, 1]")
        children.add(edge.child_evidence_id)
    for evidence_id in evidence_ids:
        origin_for(evidence_id, edges)
