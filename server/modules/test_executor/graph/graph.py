"""
Lightweight directed graph for Akto test execution orchestration.
Each node represents one HTTP request step; edges define dependencies.
"""
from enum import Enum
from dataclasses import dataclass, field


class NodeType(Enum):
    API = "api"
    CONDITION = "condition"


@dataclass
class Node:
    id: str
    type: NodeType
    data: dict = field(default_factory=dict)


class Graph:
    """Directed graph of execution nodes."""

    def __init__(self):
        self.nodes: dict[str, Node] = {}
        self.edges: dict[str, list[str]] = {}
        self.reverse: dict[str, list[str]] = {}

    def add_node(self, node: Node) -> None:
        self.nodes[node.id] = node
        self.edges.setdefault(node.id, [])
        self.reverse.setdefault(node.id, [])

    def add_edge(self, from_id: str, to_id: str) -> None:
        self.edges.setdefault(from_id, []).append(to_id)
        self.reverse.setdefault(to_id, []).append(from_id)

    def topological_order(self) -> list[str]:
        in_degree = {nid: len(preds) for nid, preds in self.reverse.items()}
        queue = [nid for nid, deg in in_degree.items() if deg == 0]
        order = []
        while queue:
            nid = queue.pop(0)
            order.append(nid)
            for succ in self.edges.get(nid, []):
                in_degree[succ] -= 1
                if in_degree[succ] == 0:
                    queue.append(succ)
        return order

    def is_leaf(self, node_id: str) -> bool:
        return len(self.edges.get(node_id, [])) == 0
