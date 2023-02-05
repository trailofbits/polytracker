from abc import abstractmethod
from typing import Iterator, Optional, Tuple

from .graphs import DAG
from .inputs import Input
from .plugins import Command, Subcommand

import networkx as nx


class TaintForestNode:
    def __init__(
        self, label: int, source: Optional[Input], affected_control_flow: bool = False
    ):
        self.label: int = label
        self.source: Optional[Input] = source
        self.affected_control_flow: bool = affected_control_flow

        # https://graphviz.org/doc/info/colors.html
        self.color = "webgrey"
        self.fontcolor = "webgrey"
        self.style = "filled"
        self.fillcolor = "ghostwhite"

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
            if node.affected_control_flow:
                # make sure all control flow affecting things get coloured
                # https://graphviz.org/doc/info/colors.html
                node.color = "black"
                node.fontcolor = "black"
                node.fillcolor = "webgrey"

            dag.add_node(
                node.label,
                # if this is a source node, it has a source: Input member
                source=node.source,
                # elsewise, it has one or two parents
                parent_one=node.parent_one,
                parent_two=node.parent_two,
                color=node.color,
                fontcolor=node.fontcolor,
                fillcolor=node.fillcolor,
                style=node.style,)

            if node.parent_one:
                dag.add_edge(node.parent_one.label, node.label, color="webgrey")

            if node.parent_two:
                dag.add_edge(node.parent_two.label, node.label, color="webgrey")

        return DAG(dag)

    def to_tainted_control_flow_graph(self) -> DAG[TaintForestNode]:
        """Returns a subset of the overall taint forest with ONLY control-flow-affecting nodes.

        TODO fill node colour by source taint / origin bytes
        TODO node text and outline colour by basic block
        """
        dag: nx.DiGraph = nx.DiGraph()

        for node in self:
            if node.affected_control_flow:
                dag.add_node(
                    node.label,
                    # if this is a source node, it has a source: Input member
                    source=node.source,
                    # elsewise, it has one or two parents
                    parent_one=node.parent_one,
                    parent_two=node.parent_two,
                    color=node.color,
                    fontcolor=node.fontcolor,
                    fillcolor=node.fillcolor,
                    style=node.style,)

                if node.parent_one:
                    dag.add_edge(node.parent_one.label, node.label, color=node.parent_one.color)

                if node.parent_two:
                    dag.add_edge(node.parent_two.label, node.label, color=node.parent_two.color)

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
        parser.add_argument("-t", type=str, help="the trace TDAG file (probably called polytracker.tdag)", dest="POLYTRACKER_DB")
        parser.add_argument(
            "-o", type=str, help="name to save resulting .dot information as", dest="OUTPUT_PATH"
        )

    def node_labeller(self, node) -> str:
        def label_by_offset(source: Input) -> str:
            label = f"[{source.track_start}]"
            if source.track_end is not None:
                label = f"[{source.track_start} - {source.track_end}]"
            return label

        print(node)

        if isinstance(node, TaintForestNode) and node.source is not None:
            return label_by_offset(node.source)
        elif isinstance(node, tuple):
            #networkx DAG tuple[label, dict]
            attributes = node[1]
            if attributes.get('source') is not None:
                source = attributes.get('source')
                return label_by_offset(source)
            elif attributes.get('parent_one') is not None:
                return self.node_labeller(attributes['parent_one'])
            elif attributes.get('parent_two') is not None:
                return self.node_labeller(attributes['parent_two'])
        elif node.parent_one is not None:
            #TDTaintForestNode
            return self.node_labeller(node.parent_one)
        elif node.parent_two is not None:
            #TDTaintForestNode
            return self.node_labeller(node.parent_two)


    def run(self, args):
        from . import PolyTrackerTrace

        trace = PolyTrackerTrace.load(args.POLYTRACKER_DB)
        graph: DAG[TaintForestNode] = trace.taint_forest.to_graph()
        graph.to_dot(labeler=self.node_labeller).save(args.OUTPUT_PATH)
        pdf = args.OUTPUT_PATH.split(".dot")[0]
        print(f"Exported the taint forest to {args.OUTPUT_PATH}")
        print(
            f"To render it to a PDF, run `dot -Tpdf -o {pdf}.pdf {args.OUTPUT_PATH}`"
        )

class ExportControlFlowLog(Subcommand):
    parent_type = ExportTaintForest

    name = "cfl"
    help = "export the control-flow-affecting subsection of the taint forest to GraphViz (DOT) format"

    def __init_arguments__(self, parser):
        parser.add_argument("-t", type=str, help="the trace TDAG file (probably called polytracker.tdag)", dest="POLYTRACKER_DB")
        parser.add_argument(
            "-o", type=str, help="name to save resulting .dot information as", dest="OUTPUT_PATH"
        )

    def run(self, args):
        from . import PolyTrackerTrace

        trace = PolyTrackerTrace.load(args.POLYTRACKER_DB)
        graph: DAG[TaintForestNode] = trace.taint_forest.to_tainted_control_flow_graph()
        graph.to_dot().save(args.OUTPUT_PATH)
        pdf = args.OUTPUT_PATH.split(".dot")[0]
        print(f"Exported the control-flow-affecting subsection of the taint forest to {args.OUTPUT_PATH}")
        print(
            f"To render it to a PDF, run `dot -Tpdf -o {pdf}.pdf {args.OUTPUT_PATH}`"
        )