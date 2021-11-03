from abc import abstractmethod
from typing import Iterator, Optional

from .graphs import DAG
from .inputs import Input
from .plugins import Command


class TaintForestNode:
    def __init__(self, label: int, source: Input):
        self.label: int = label
        self.source: Input = source

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
        return isinstance(other, TaintForestNode) and other.label == self.label and other.source == self.source

    def __hash__(self):
        return hash((self.label, self.source))


class TaintForest:
    @abstractmethod
    def nodes(self) -> Iterator[TaintForestNode]:
        raise NotImplementedError()

    def to_graph(self) -> DAG[TaintForestNode]:
        # TODO
        raise NotImplementedError()

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
        parser.add_argument("OUTPUT_PATH", type=str, help="path to which to save the .dot file")

    def run(self, args):
        from . import PolyTrackerTrace

        trace = PolyTrackerTrace.load(args.POLYTRACKER_DB)
        graph = trace.taint_forest.to_graph()
        graph.to_dot().save(args.OUTPUT_PATH)
        print(f"Exported the taint forest to {args.OUTPUT_PATH}")
        print(f"To render it to a PDF, run `dot -Tpdf -o taint_forest.pdf {args.OUTPUT_PATH}`")
