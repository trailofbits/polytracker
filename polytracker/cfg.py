import math

from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    FrozenSet,
    Generic,
    ItemsView,
    Iterable,
    Iterator,
    KeysView,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

import cxxfilt
import graphviz
import networkx as nx
import os

from .cache import OrderedSet


N = TypeVar("N")
D = TypeVar("D", bound="DiGraph")


class DiGraph(nx.DiGraph, Generic[N]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dominator_forest: Optional[DiGraph[N]] = None
        self._roots: Optional[Collection[N]] = None
        self._path_lengths: Optional[Dict[N, Dict[N, int]]] = None

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
        comment: Optional[str] = None,
        labeler: Optional[Callable[[N], str]] = None,
        node_filter=None,
    ) -> graphviz.Digraph:
        if comment is not None:
            dot = graphviz.Digraph(comment=comment)
        else:
            dot = graphviz.Digraph()
        if labeler is None:
            labeler = str
        node_ids = {node: i for i, node in enumerate(self.nodes)}
        for node in self.nodes:
            if node_filter is None or node_filter(node):
                dot.node(f"func{node_ids[node]}", label=labeler(node))
        for caller, callee in self.edges:
            if node_filter is None or (node_filter(caller) and node_filter(callee)):
                dot.edge(f"func{node_ids[caller]}", f"func{node_ids[callee]}")
        return dot


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


class FunctionInfo:
    def __init__(
        self,
        name: str,
        cmp_bytes: Dict[str, List[int]],
        input_bytes: Optional[Dict[str, List[int]]] = None,
        called_from: Iterable[str] = (),
    ):
        self.name: str = name
        self.called_from: FrozenSet[str] = frozenset(called_from)
        self._cmp_bytes: Dict[str, List[int]] = cmp_bytes
        if input_bytes is None:
            self._input_bytes: Dict[str, List[int]] = cmp_bytes
        else:
            self._input_bytes = input_bytes
        self._demangled_name: Optional[str] = None

    @property
    def demangled_name(self) -> str:
        if self._demangled_name is None:
            self._demangled_name = self.name
            if self._demangled_name.startswith("dfs$"):
                self._demangled_name = self._demangled_name[4:]
            self._demangled_name = cxxfilt.demangle(self._demangled_name)
        return self._demangled_name  # type: ignore

    def source_size(self, source: str) -> int:
        if source not in self.taint_sources:
            raise KeyError(source)
        elif os.path.exists(source):
            return os.stat(source).st_size
        else:
            # find the largest byte this trace touched
            return max(self.input_bytes.get(source, default=[]))

    def taint_source_sizes(self) -> Dict[str, int]:
        return {source: self.source_size(source) for source in self.taint_sources}

    @property
    def input_bytes(self) -> Dict[str, List[int]]:
        return self._input_bytes

    @property
    def cmp_bytes(self) -> Dict[str, List[int]]:
        return self._cmp_bytes

    @property
    def taint_sources(self) -> KeysView[str]:
        return self.input_bytes.keys()

    @staticmethod
    def tainted_chunks(byte_offsets: Iterable[int]) -> Iterator[Tuple[int, int]]:
        start_offset: Optional[int] = None
        last_offset: Optional[int] = None
        for offset in sorted(byte_offsets):
            if last_offset is None:
                start_offset = offset
            elif offset != last_offset and offset != last_offset + 1:
                yield start_offset, last_offset + 1  # type: ignore
                start_offset = offset
            last_offset = offset
        if last_offset is not None:
            yield start_offset, last_offset + 1  # type: ignore

    def input_chunks(self) -> Iterator[Tuple[str, Tuple[int, int]]]:
        for source, byte_offsets in self.input_bytes.items():
            for start, end in FunctionInfo.tainted_chunks(byte_offsets):
                yield source, (start, end)

    def cmp_chunks(self) -> Iterator[Tuple[str, Tuple[int, int]]]:
        for source, byte_offsets in self.cmp_bytes.items():
            for start, end in FunctionInfo.tainted_chunks(byte_offsets):
                yield source, (start, end)

    def __getitem__(self, input_source_name: str) -> List[int]:
        return self.input_bytes[input_source_name]

    def __iter__(self) -> Iterable[str]:
        return self.taint_sources

    def items(self) -> ItemsView[str, List[int]]:
        return self.input_bytes.items()

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return isinstance(other, FunctionInfo) and other.name == self.name

    def __str__(self):
        return self.demangled_name

    def __repr__(self):
        return f"{self.__class__.__name__}(name={self.name!r}, cmp_bytes={self.cmp_bytes!r}, "\
               f"input_bytes={self.input_bytes!r}, called_from={self.called_from!r})"


class CFG(DiGraph[FunctionInfo]):
    def __init__(self):
        super().__init__()

    def to_dot(
        self,
        comment: Optional[str] = "PolyTracker Program Trace",
        labeler: Optional[Callable[[FunctionInfo], str]] = None,
        node_filter=None,
    ) -> graphviz.Digraph:
        function_labels: Dict[str, str] = {}

        def func_labeler(f):
            if labeler is not None:
                return labeler(f)
            elif f.name in function_labels:
                return f"{f.name} ({function_labels[f.name]})"
            else:
                return f.name

        return super().to_dot(comment, labeler=func_labeler, node_filter=node_filter)


G = TypeVar("G", bound=nx.DiGraph)


def non_disjoint_union_all(first_graph: G, *graphs: G) -> G:
    edges: Set[Tuple[Any, Any]] = set(first_graph.edges)
    for graph in graphs:
        edges |= graph.edges
    return first_graph.__class__(list(edges))
