from abc import abstractmethod
from typing import Iterator, Optional, Tuple

from .graphs import DAG
from .inputs import Input
from .plugins import Command

import networkx as nx


class TaintForestNode:
    def __init__(
        self, label: int, source: Optional[Input], affected_control_flow: bool = False
    ):
        self.label: int = label
        self.source: Optional[Input] = source
        self.affected_control_flow: bool = affected_control_flow

    @property
    @abstractmethod
    def parent_labels(self) -> Optional[Tuple[int, int]]:
        raise NotImplementedError()

    @property
    @abstractmethod
    def parent_one(self) -> Optional["TaintForestNode"]:
        raise NotImplementedError()

    @property
    @abstractmethod
    def parent_two(self) -> Optional["TaintForestNode"]:
        raise NotImplementedError()

    def is_canonical(self) -> bool:
        return self.parent_one is None and self.parent_two is None

    def __eq__(self, other):
        return (
            isinstance(other, TaintForestNode)
            and other.label == self.label
            and other.source == self.source
        )

    def __lt__(self, other):
        return isinstance(other, TaintForestNode) and self.label < other.label

    def __hash__(self):
        return hash((self.label, self.source))


class TaintForest:
    @abstractmethod
    def nodes(self) -> Iterator[TaintForestNode]:
        """Iterates over the nodes in order of decreasing label"""
        raise NotImplementedError()

    @abstractmethod
    def get_node(self, label: int, source: Optional[Input] = None) -> TaintForestNode:
        raise NotImplementedError()

    @abstractmethod
    def __getitem__(self, label: int) -> Iterator[TaintForestNode]:
        raise NotImplementedError()

    def to_graph(self) -> DAG[TaintForestNode]:
        dag: nx.DiGraph = nx.DiGraph()

        for node in self:
            dag.add_node(node.label)
            if node.parent_one:
                dag.add_edge(node.parent_one.label, node.label)

            if node.parent_two:
                dag.add_edge(node.parent_two.label, node.label)

        return DAG(dag)

    def __iter__(self):
        return self.nodes()

    @abstractmethod
    def __len__(self):
        raise NotImplementedError()


class ExportTaintForest(Command):
    name = "forest"
    help = "export a taint forest to GraphViz (DOT) format"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_DB", type=str, help="the trace database")
        parser.add_argument(
            "OUTPUT_PATH", type=str, help="path to which to save the .dot file"
        )

    def run(self, args):
        from . import PolyTrackerTrace

        trace = PolyTrackerTrace.load(args.POLYTRACKER_DB)
        graph = trace.taint_forest.to_graph()
        graph.to_dot().save(args.OUTPUT_PATH)
        print(f"Exported the taint forest to {args.OUTPUT_PATH}")
        print(
            f"To render it to a PDF, run `dot -Tpdf -o taint_forest.pdf {args.OUTPUT_PATH}`"
        )
