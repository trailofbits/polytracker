import math

from typing import (
    Callable,
    Collection,
    Dict,
    FrozenSet,
    Generic,
    ItemsView,
    Iterable,
    KeysView,
    List,
    Optional,
    Set,
    TypeVar,
    Union,
)

import graphviz
import networkx as nx

N = TypeVar("N")


class DiGraph(nx.DiGraph, Generic[N]):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dominator_forest: Optional[DiGraph[N]] = None
        self._roots: Optional[Collection[N]] = None
        self._path_lengths: Optional[Dict[N, Dict[N, int]]] = None

    def path_length(self, from_node: N, to_node: N) -> Union[int, float]:
        if self._path_lengths is None:
            self._path_lengths = dict(nx.all_pairs_shortest_path_length(self, cutoff=None))
        if from_node not in self._path_lengths or to_node not in self._path_lengths[from_node]:
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

    def ancestors(self, node: N) -> Set[N]:
        return nx.ancestors(self, node)

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
        self, comment: Optional[str] = None, labeler: Optional[Callable[[N], str]] = None, node_filter=None
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
        input_bytes: Dict[str, List[int]] = None,
        called_from: Iterable[str] = (),
    ):
        self.name: str = name
        self.called_from: FrozenSet[str] = frozenset(called_from)
        self.cmp_bytes: Dict[str, List[int]] = cmp_bytes
        if input_bytes is None:
            self.input_bytes: Dict[str, List[int]] = cmp_bytes
        else:
            self.input_bytes = input_bytes

    @property
    def taint_sources(self) -> KeysView[str]:
        return self.input_bytes.keys()

    def __getitem__(self, input_source_name: str) -> List[int]:
        return self.input_bytes[input_source_name]

    def __iter__(self) -> Iterable[str]:
        return self.taint_sources

    def items(self) -> ItemsView[str, List[int]]:
        return self.input_bytes.items()

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return self.name

    def __repr__(self):
        return f"{self.__class__.__name__}(name={self.name!r}, cmp_bytes={self.cmp_bytes!r}, input_bytes={self.input_bytes!r}, called_from={self.called_from!r})"


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
