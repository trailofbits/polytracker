import math

from typing import Any, Callable, Optional

import graphviz
import networkx as nx


def roots(graph):
    return (n for n, d in graph.in_degree() if d == 0)


class DiGraph(nx.DiGraph):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dominator_forest: Optional[DiGraph] = None
        self._roots = None
        self._path_lengths = None

    def path_length(self, from_node, to_node):
        if self._path_lengths is None:
            self._path_lengths = dict(nx.all_pairs_shortest_path_length(self, cutoff=None))
        if from_node not in self._path_lengths or to_node not in self._path_lengths[from_node]:
            return math.inf
        else:
            return self._path_lengths[from_node][to_node]

    def set_roots(self, roots):
        self._roots = roots

    @property
    def roots(self):
        if self._roots is None:
            self._roots = tuple(roots(self))
        return self._roots

    def depth(self, node):
        return min(self.path_length(root, node) for root in self.roots)

    def ancestors(self, node) -> set:
        return nx.ancestors(self, node)

    def descendants(self, node) -> frozenset:
        return frozenset(nx.dfs_successors(self, node).keys())

    @property
    def dominator_forest(self):
        if self._dominator_forest is not None:
            return self._dominator_forest
        self._dominator_forest = DAG()
        for root in self.roots:
            for node, dominated_by in nx.immediate_dominators(self, root).items():
                if node != dominated_by:
                    self._dominator_forest.add_edge(dominated_by, node)
        return self._dominator_forest

    def to_dot(self, comment: str = None, labeler=Callable[[Any], str], node_filter=None) -> graphviz.Digraph:
        if comment is not None:
            dot = graphviz.Digraph(comment=comment)
        else:
            dot = graphviz.Digraph()
        node_ids = {node: i for i, node in enumerate(self.nodes)}
        for node in self.nodes:
            if node_filter is None or node_filter(node):
                dot.node(f"func{node_ids[node]}", label=labeler(node))
        for caller, callee in self.edges:
            if node_filter is None or (node_filter(caller) and node_filter(callee)):
                dot.edge(f"func{node_ids[caller]}", f"func{node_ids[callee]}")
        return dot


class DAG(DiGraph):
    def vertex_induced_subgraph(self, vertices):
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


class CFG(DiGraph):
    def __init__(self):
        super().__init__()

    def to_dot(
        self, comment="PolyTracker Program Trace", merged_json_obj=None, only_labeled_functions=False, labeler=None, **kwargs
    ) -> graphviz.Digraph:
        function_labels = {}

        def func_labeler(f):
            if labeler is not None:
                return labeler(f)
            elif f.name in function_labels:
                return f"{f.name} ({function_labels[f.name]})"
            else:
                return f.name

        return super().to_dot(comment, labeler=func_labeler, **kwargs)
