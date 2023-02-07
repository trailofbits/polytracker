import math
from typing import (
    TypeVar,
    Generic,
    Optional,
    Collection,
    Dict,
    Union,
    Iterable,
    Callable,
    Set,
    FrozenSet,
    Tuple,
    Any,
)

import graphviz
import networkx as nx

from polytracker.cache import OrderedSet

N = TypeVar("N")
T = TypeVar("T")
D = TypeVar("D", bound="DiGraph")


class DiGraph(nx.DiGraph, Generic[N]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dominator_forest: Optional[DiGraph[N]] = None
        self._roots: Optional[Collection[N]] = None
        self._path_lengths: Optional[Dict[N, Dict[N, int]]] = None
        # self.nodes will normally give you a NodeView which we treat
        # as a list[N] here, e.g. NodeView(('hi', 'hello')) but if you want
        # properties for each node, set data=True.
        # example properties view: NodeDataView({'hi': {'source': None, 'color': 'green', 'font_weight': 'bold'}, 'hello': {'source': 'hi', 'color': 'blue'}})
        self._nodes_with_properties = self.nodes(data=True)

    def path_length(self, from_node: N, to_node: N) -> Union[int, float]:
        if self._path_lengths is None:
            self._path_lengths = dict(
                nx.all_pairs_shortest_path_length(self, cutoff=None)
            )
        if (
            from_node not in self._path_lengths
            or to_node not in self._path_lengths[from_node]
        ):
            return math.inf
        else:
            return self._path_lengths[from_node][to_node]

    def set_roots(self, roots: Collection[N]):
        self._roots = roots

    def _find_roots(self) -> Iterable[N]:
        return (n for n, d in self.in_degree() if d == 0)

    @property
    def roots(self) -> Collection[N]:
        if self._roots is None:
            self._roots = tuple(self._find_roots())
        return self._roots

    def depth(self, node: N) -> Union[int, float]:
        return min(self.path_length(root, node) for root in self.roots)

    def ancestors(self, node: N) -> OrderedSet[N]:
        if not self.has_node(node):
            raise nx.NetworkXError(f"Node {node} is not in the graph")
        return OrderedSet(
            *(
                x
                for _, x in sorted(
                    (d, n)
                    for n, d in nx.shortest_path_length(self, target=node).items()
                    if n is not node
                )
            )
        )

    def has_one_predecessor(self, node: N) -> bool:
        """Returns whether the given node has exactly one predecessor"""
        i = iter(self.predecessors(node))
        try:
            next(i)
        except StopIteration:
            # it has no predecessors
            return False
        try:
            next(i)
            # it has more than one predecessor
            return False
        except StopIteration:
            # it has exactly one predecessor
            return True

    def contract(self: D, union: Callable[[N, N], N] = lambda n, _: n) -> D:
        """
        Simplifies this graph by merging nodes with exactly one predecessor to its predecessor.

        Args:
            union: An optional callback function that returns the union of two merged nodes. If omitted, the first node
                will be used.

        Returns:
            A new, simplified graph of the same type.

        """
        nodes: Set[N] = set(self.nodes)
        ret: D = self.__class__()
        ret.add_edges_from(self.edges)
        while nodes:
            node = next(iter(nodes))
            nodes.remove(node)
            if self.has_one_predecessor(node):
                pred: N = next(iter(self.predecessors(node)))
                new_node: N = union(pred, node)
                incoming_nodes = list(self.predecessors(pred))
                outgoing_nodes = list(self.successors(node))
                ret.remove_nodes_from([pred, node])
                ret.add_edges_from(
                    [(i, new_node) for i in incoming_nodes]
                    + [(new_node, o) for o in outgoing_nodes]
                )
                if new_node is not pred:
                    nodes.remove(pred)
                    nodes.add(new_node)
        return ret

    def descendants(self, node: N) -> FrozenSet[N]:
        return frozenset(nx.dfs_successors(self, node).keys())

    @property
    def dominator_forest(self) -> "DAG[N]":
        if self._dominator_forest is not None:
            return self._dominator_forest
        self._dominator_forest = DAG()
        for root in self.roots:
            for node, dominated_by in nx.immediate_dominators(self, root).items():
                if node != dominated_by:
                    self._dominator_forest.add_edge(dominated_by, node)
        return self._dominator_forest

    def to_dot(
        self,
        trace: T,
        comment: Optional[str] = None,
        labeler: Optional[Callable[[N, T], str]] = None,
        node_filter=None,
    ) -> graphviz.Digraph:
        if labeler is None:
            labeler = str

        def default_node_filter(x: Any) -> bool:
            return True

        if node_filter is None:
            node_filter = default_node_filter
        # Sort nodes into roots and inner nodes
        root_nodes: list[N] = []
        inner_nodes: list[N] = []
        for node in sorted(filter(node_filter, self._nodes_with_properties)):
            # _nodes_with_properties is a list of tuples (int, dict[str, str])
            # from the underlying nx.DiGraph we initialised this class with.
            # the first member is the integer node label.
            if node[0] in self.roots:
                root_nodes.append(node)
            else:
                inner_nodes.append(node)

        # Add root nodes
        roots = graphviz.Digraph(
            name="roots",
            graph_attr={"rank": "same"},
            node_attr={"shape": "square"},
            edge_attr={"style": "invis"},
        )

        for root in root_nodes:
            roots.node(
                str(root[0]),
                label=labeler(root, trace),
                color=root[1].get('color'),
                fontcolor=root[1].get('fontcolor'),
                fillcolor=root[1].get('fillcolor'),
                style=root[1].get('style'),)

        # Add invisible edges to enforce root node ordering within a rank
        for i in range(len(root_nodes) - 1):
            roots.edge(str(root_nodes[i][0]), str(root_nodes[i + 1][0]))

        # Add inner nodes
        inners = graphviz.Digraph(name="inner")

        for inner in inner_nodes:
            inners.node(
                str(inner[0]),
                label=labeler(inner, trace),
                color=inner[1].get('color'),
                fontcolor=inner[1].get('fontcolor'),
                fillcolor=inner[1].get('fillcolor'),
                style=inner[1].get('style'),)

        result = graphviz.Digraph(comment=comment)
        result.subgraph(roots)
        result.subgraph(inners)
        for src, dst in self.edges:
            if node_filter(src) and node_filter(dst):
                result.edge(str(src), str(dst))
        return result


class DAG(DiGraph[N], Generic[N]):
    def vertex_induced_subgraph(self, vertices: Iterable[N]) -> "DAG[N]":
        vertices = frozenset(vertices)
        subgraph = self.copy()
        to_remove = set(self.nodes) - vertices
        for v in vertices:
            node = v
            parent = None
            while True:
                parents = tuple(subgraph.predecessors(node))
                if not parents:
                    if parent is not None:
                        subgraph.remove_edge(parent, v)
                        subgraph.add_edge(node, v)
                    break
                assert len(parents) == 1
                ancestor = parents[0]
                if parent is None:
                    parent = ancestor
                if ancestor in vertices:
                    to_remove.add(v)
                    break
                node = ancestor
        subgraph.remove_nodes_from(to_remove)
        return subgraph


G = TypeVar("G", bound=nx.DiGraph)


def non_disjoint_union_all(first_graph: G, *graphs: G) -> G:
    edges: Set[Tuple[Any, Any]] = set(first_graph.edges)
    for graph in graphs:
        edges |= graph.edges
    return first_graph.__class__(list(edges))
