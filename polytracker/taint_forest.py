from abc import abstractmethod
from typing import Iterator, Optional, Tuple, Set

from .graphs import DAG
from .inputs import Input
from .plugins import Command, Subcommand

import networkx as nx


class TaintForestNode:
    def __init__(
        self,
        label: int,
        source: Optional[Input],
        affected_control_flow: bool = False,
    ):
        self.label: int = label

        # Each "source" node has a link back to the sole Input
        # (fd, path, stream...) which this Taint Forest represents.
        # We can use the trace-level file offset calculator to
        # find out this node's place in the world via self.label.
        # self.source should be None if this node has node parents.
        self.source: Optional[Input] = source

        self.affected_control_flow: bool = affected_control_flow

        # https://graphviz.org/doc/info/colors.html
        self.color = "black"
        self.fontcolor = "black"
        self.style = "filled"
        self.fillcolor = "ghostwhite"

        self.offset: Set[int] = set()

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

    def offsets_to_string(self) -> str:
        """Return the list of offsets which influenced this node, as a string, for use in the DOT output representation of a taint forest or control flow affecting data graph."""
        return ", ".join(str(offset) for offset in sorted(self.offset))

    def update_offsets(self, new_offsets: set[int]) -> str:
        """Given trace information sourced in node_labeller(), update this node's offset, which we will use to (re)label the resulting Taint Forest DAG and the DAG-descriptive DOT.

        This is not a complete offset sourcing - it still requires you to look the label up in the program trace. It's mostly for caching while building the DOT which represents the taint forest DAG."""
        print (f"OFFSET set for {self.label} before set: {self.offset}")

        self.offset.update(new_offsets)

        if self.source is not None:
            # only other node types can have more than one influencing offset
            assert len(self.offset) == 1

        print (f"node: OFFSET for {self.label} IS NOW {self.offset}")
        # graphviz will show edges in an order that does not necessarily match,
        # even unsorted
        return self.offsets_to_string()


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
            print(f"yo node {node}")
            if node.affected_control_flow:
                # https://graphviz.org/doc/info/colors.html
                node.color = "black"
                node.fontcolor = "black"
                node.fillcolor = "webgrey"

            dag.add_node(
                node.label,
                # if this is a source node, it has a reference back to the input
                source=node.source,
                # elsewise, it has one or two parents
                parent_one=node.parent_one,
                parent_two=node.parent_two,
               # offset=node.offset,
                color=node.color,
                fontcolor=node.fontcolor,
                fillcolor=node.fillcolor,
                style=node.style,)

            if node.parent_one:
                dag.add_edge(node.parent_one.label, node.label)

            if node.parent_two:
                dag.add_edge(node.parent_two.label, node.label)

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

    def node_labeller(self, node, trace) -> str:
        """Iterate back up the chain of each node's parents to build the list of offsets which taint it, on the spot.
        """
        if isinstance(node, TaintForestNode):
            if node.source is not None:
                offset_from_trace = trace.file_offset(node)
                print(f"SOURCE NODE {node.label}. existing offset {node.offset}, adding {offset_from_trace.offset}")
                return node.update_offsets(set([offset_from_trace.offset]))
            else:
                if node.parent_one is not None:
                    self.node_labeller(node.parent_one, trace)
                    if len(node.parent_one.offset) > 0:
                        print(f"CHILD NODE {node.label}. existing offset {node.offsets_to_string()}, adding parent ONE offsets {node.parent_one.offsets_to_string()}")
                        node.update_offsets(node.parent_one.offset)
                if node.parent_two is not None:
                    self.node_labeller(node.parent_two, trace)
                    if len(node.parent_two.offset) > 0:
                        print(f"CHILD NODE {node.label}. existing offset {node.offsets_to_string()}, adding parent TWO offsets {node.parent_two.offsets_to_string()}")
                        return node.update_offsets(node.parent_two.offset)
        elif isinstance(node, tuple):
            # convert to a node in the graph, and return a label based on that
            tf_node: TaintForestNode = trace.tforest.get_node(node[0])
            print(f"converted tuple {node} into taint forest node...")
            return self.node_labeller(tf_node, trace)
        else:
            return "???"

    def run(self, args):
        from . import PolyTrackerTrace

        trace = PolyTrackerTrace.load(args.POLYTRACKER_DB)
        graph: DAG[TaintForestNode] = trace.taint_forest.to_graph()
        graph.to_dot(trace, labeler=self.node_labeller).save(args.OUTPUT_PATH)
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
        graph.to_dot(trace, labeler=self.node_labeller).save(args.OUTPUT_PATH)
        pdf = args.OUTPUT_PATH.split(".dot")[0]
        print(f"Exported the control-flow-affecting subsection of the taint forest to {args.OUTPUT_PATH}")
        print(
            f"To render it to a PDF, run `dot -Tpdf -o {pdf}.pdf {args.OUTPUT_PATH}`"
        )