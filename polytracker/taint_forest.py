from abc import abstractmethod
from typing import Iterator, Optional, Tuple

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
        self.source: Optional[Input] = source
        self.affected_control_flow: bool = affected_control_flow

        # https://graphviz.org/doc/info/colors.html
        self.color = "black"
        self.fontcolor = "black"
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

    def _label_by_offset(self, byte_offset_start: int, node: TaintForestNode) -> str:
        """Given trace information sourced in node_labeller(), update this node's offset, which we will use to (re)label the resulting DOT graph."""
        offset = f"{byte_offset_start}"
        # update node, and use value later where we called this labelling fn
        if hasattr(node, 'offset') and offset not in node.offset:
            node.offset = f"{node.offset}, {offset}"
        else:
            node.offset = offset
        print (f"OFFSET for {node.label} IS NOW {node.offset}")
        return node.offset

    def node_labeller(self, node, trace, label=None) -> str:
        """A node might not know its own offsets; iterate its right and left parents to build the list of offsets which taint it on the spot."""

        if isinstance(node, TaintForestNode) and node.source is not None:
            # source node (no parents), so we can look up its offset directly
            offset = trace.file_offset(node)
            print(f"SOURCE offset version: o {offset.offset}, l {offset.length} (existing label: {label})")
            if not hasattr(node, "offset"):
                node.offset = label
            return self._label_by_offset(offset.offset, node)
        elif isinstance(node, tuple):
            #networkx DAG tuple[label, dict] needs to be translated into a TaintForestNode to be able ot be labelled
            tf_node = trace.tforest.get_node(node[0])
            if tf_node.source is not None:
                offset = trace.file_offset(tf_node)
                print(f"DAG TUPLE SOURCE node offset version: o {offset.offset}, l {offset.length}, (existing label: {label})")
                if not hasattr(node, "offset") and label is not None:
                    tf_node.offset = label
                return self._label_by_offset(offset.offset, tf_node)
            else:
                if tf_node.parent_one is not None:
                    print("iterating over the parent ONE node to label this node")
                    label = self.node_labeller(tf_node.parent_one, trace)

                if tf_node.parent_two is not None:
                    print("iterating over the parent TWO node to label this node")
                    return self.node_labeller(tf_node.parent_one, trace, label)
        elif node.parent_one is not None:
        # node is a TDTaintForestNode so we want to check both its parents
        # for tainted offsets. A node can be tainted by either left (one),
        # right (two), or if both exist, both left and right parents.
            if node.parent_one.source is None or node.parent_two.source is None:
                print("checking left and right...")
                label = self.node_labeller(node.parent_one, trace)
                return self.node_labeller(node.parent_two, trace, label)
            else:
                offset_one = node.parent_one.forest.trace.file_offset(node.parent_one)
                print(f"ONE possible offset version: o {offset_one.offset}, l {offset_one.length}")
                if not hasattr(node, "offset") and label is not None:
                    node.offset = label
                self._label_by_offset(offset_one.offset, node)

                offset_two = node.parent_two.forest.trace.file_offset(node.parent_two)
                print(f"TWO possible offset version: o {offset_two.offset}, l {offset_two.length}")
                if not hasattr(node, "offset") and label is not None:
                    node.offset = label
                return self._label_by_offset(offset_two.offset, node)
        else:
            # no label :(
            print("how did ew get here???")



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