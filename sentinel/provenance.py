from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.types import Artifact


@dataclass
class ProvenanceNode:
    artifact_id: str
    source_tool: str
    labels: set[str] = field(default_factory=set)
    parents: set[str] = field(default_factory=set)
    summary: str = ""


class ProvenanceGraph:
    """Small provenance graph for artifact label propagation."""

    def __init__(self) -> None:
        self.nodes: dict[str, ProvenanceNode] = {}

    def add_artifact(
        self,
        artifact: Artifact,
        parents: set[str] | frozenset[str] = frozenset(),
        summary: str = "",
    ) -> Artifact:
        effective_labels = set(artifact.labels)
        for parent_id in parents:
            effective_labels.update(self.labels_for_artifact(parent_id))

        node = ProvenanceNode(
            artifact_id=artifact.artifact_id,
            source_tool=artifact.source_tool,
            labels=effective_labels,
            parents=set(parents),
            summary=summary or artifact.value[:120],
        )
        self.nodes[artifact.artifact_id] = node
        return Artifact(
            artifact_id=artifact.artifact_id,
            value=artifact.value,
            labels=frozenset(effective_labels),
            source_tool=artifact.source_tool,
        )

    def labels_for_artifact(self, artifact_id: str) -> set[str]:
        node = self.nodes.get(artifact_id)
        if node is None:
            return set()
        labels = set(node.labels)
        for parent_id in node.parents:
            labels.update(self.labels_for_artifact(parent_id))
        return labels

    def labels_for(self, artifact_ids: set[str] | frozenset[str]) -> frozenset[str]:
        labels: set[str] = set()
        for artifact_id in artifact_ids:
            labels.update(self.labels_for_artifact(artifact_id))
        return frozenset(labels)

    def subgraph_for(self, artifact_ids: set[str] | frozenset[str]) -> dict[str, Any]:
        seen: set[str] = set()

        def visit(artifact_id: str) -> None:
            if artifact_id in seen:
                return
            seen.add(artifact_id)
            node = self.nodes.get(artifact_id)
            if node is None:
                return
            for parent_id in node.parents:
                visit(parent_id)

        for artifact_id in artifact_ids:
            visit(artifact_id)

        return {
            artifact_id: self.node_to_dict(self.nodes[artifact_id])
            for artifact_id in sorted(seen)
            if artifact_id in self.nodes
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            artifact_id: self.node_to_dict(node)
            for artifact_id, node in sorted(self.nodes.items())
        }

    def format(self) -> str:
        if not self.nodes:
            return "  none"
        lines = []
        for artifact_id, node in sorted(self.nodes.items()):
            labels = ", ".join(sorted(node.labels)) if node.labels else "none"
            parents = f"({', '.join(sorted(node.parents))})" if node.parents else ""
            source = f"{node.source_tool}{parents}" if parents else node.source_tool
            lines.append(f"  {artifact_id} [{labels}] <- {source}")
        return "\n".join(lines)

    @staticmethod
    def node_to_dict(node: ProvenanceNode) -> dict[str, Any]:
        return {
            "artifact_id": node.artifact_id,
            "source_tool": node.source_tool,
            "labels": sorted(node.labels),
            "parents": sorted(node.parents),
            "summary": node.summary,
        }
