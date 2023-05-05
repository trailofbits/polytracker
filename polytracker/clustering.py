"""
The `clusters` command.
"""

from typing import (
    Tuple,
    Set,
    List,
    Optional,
    Sequence,
    Union,
    TypeVar,
    FrozenSet,
    Generic,
    Dict,
    Iterable,
)

from .plugins import Command
from .taint_dag import TDFile, TDSourceNode, TDUnionNode, TDRangeNode
from pathlib import Path

from itertools import product
from collections import defaultdict
from graphtage.matching import get_dtype
import numpy as np
from scipy.optimize import linear_sum_assignment
import networkx as nx
from tqdm import tqdm

T = TypeVar("T")


def edit_distance(s: Sequence[T], t: Sequence[T]) -> int:
    distance: List[List[int]] = [[0] * (len(t) + 1) for _ in range(len(s) + 1)]
    for i in range(1, len(s) + 1):
        distance[i][0] = i
    for i in range(1, len(t) + 1):
        distance[0][i] = i
    for j in range(1, len(t) + 1):
        for i in range(1, len(s) + 1):
            if s[i - 1] == t[j - 1]:
                substitution_cost = 0
            else:
                substitution_cost = 1
            distance[i][j] = min(
                distance[i - 1][j] + 1,  # deletion
                distance[i][j - 1] + 1,  # insertion
                distance[i - 1][j - 1] + substitution_cost,
            )
    return distance[len(s)][len(t)]


class IndexedSequence(Generic[T], Sequence[T]):
    def __init__(self, sequence: Sequence[T]):
        self.sequence: Tuple[T, ...] = tuple(sequence)
        self.indexes: Dict[T, Tuple[int, ...]] = {}
        for i, t in enumerate(self.sequence):
            if t in self.indexes:
                self.indexes[t] = self.indexes[t] + (i,)
            else:
                self.indexes[t] = (i,)

    def __hash__(self):
        return hash(self.sequence)

    def __len__(self):
        return len(self.sequence)

    def __bool__(self):
        return bool(self.sequence)

    def __getitem__(self, index):
        return self.sequence[index]

    def __str__(self):
        return str(self.sequence)


class Matching(Generic[T]):
    def __init__(
        self,
        s1: Union[IndexedSequence[T], Sequence[T]],
        s2: Union[IndexedSequence[T], Sequence[T]],
        mapping: Dict[T, T],
    ):
        if isinstance(s1, IndexedSequence):
            self.s1: IndexedSequence[T] = s1
        else:
            self.s1 = IndexedSequence(s1)
        if isinstance(s2, IndexedSequence):
            self.s2: IndexedSequence[T] = s2
        else:
            self.s2 = IndexedSequence(s2)
        self.mapping: Dict[T, T] = dict(mapping)
        self.unmatched_s1: FrozenSet[T] = frozenset(
            self.s1.indexes.keys() - self.mapping.keys()
        )
        self.unmatched_s2: FrozenSet[T] = frozenset(
            self.s2.indexes.keys() - set(self.mapping.values())
        )
        self._edit_distance: Optional[int] = None

    @property
    def edit_distance(self) -> int:
        if self._edit_distance is not None:
            return self._edit_distance
        distance = sum(len(self.s1.indexes[u]) for u in self.unmatched_s1) + sum(
            len(self.s2.indexes[u]) for u in self.unmatched_s2
        )
        for s, t in self.mapping.items():
            distance += edit_distance(self.s1.indexes[s], self.s2.indexes[t])
        self._edit_distance = distance
        return distance

    @property
    def similarity(self) -> float:
        max_length = max(len(self.s1), len(self.s2))
        if max_length == 0:
            return 0.0
        return 1.0 - float(self.edit_distance) / float(max_length)

    def __str__(self):
        return (
            f"{self.mapping!s} cost={self.edit_distance}, similarity={self.similarity}"
        )


def match(s1: Sequence[T], s2: Sequence[T]) -> Matching[T]:
    if not isinstance(s1, IndexedSequence):
        s1 = IndexedSequence(s1)
    if not isinstance(s2, IndexedSequence):
        s2 = IndexedSequence(s2)
    labels1 = list(s1.indexes.keys())
    labels2 = list(s2.indexes.keys())
    weights: List[List[int]] = [[0] * len(labels2) for _ in range(len(labels1))]
    min_edge: Optional[int] = None
    max_edge: Optional[int] = None
    for (i, l1), (j, l2) in product(enumerate(labels1), enumerate(labels2)):
        distance = edit_distance(s1.indexes[l1], s2.indexes[l2])
        weights[i][j] = distance
        if min_edge is None or min_edge > distance:
            min_edge = distance
        if max_edge is None or max_edge < distance:
            max_edge = distance
    dtype = get_dtype(min_edge, max_edge)
    left_matches = linear_sum_assignment(np.array(weights, dtype=dtype), maximize=False)
    return Matching(
        s1,
        s2,
        mapping={
            labels1[from_index]: labels2[to_index]
            for from_index, to_index in zip(*left_matches)
        },
    )


class Clusters(Command):
    name = "clusters"
    help = "clusters input byte offsets based on their interaction"

    def __init_arguments__(self, parser):
        parser.add_argument(
            "trace_file",
            type=Path,
            nargs="?",
            help="print clusters for a trace file",
        )

        parser.add_argument(
            "-m",
            "--match",
            type=Path,
            nargs=2,
            help="print cluster matching for two trace files",
        )

    def to_graph(self, f: TDFile) -> Tuple[nx.DiGraph, Dict[int, int]]:
        graph = nx.DiGraph()
        sources: Dict[int, int] = dict()
        offsets: Dict[int, List[int]] = defaultdict(list)
        # Create graph from TDFile
        for label, node in tqdm(enumerate(f.nodes, start=1), total=f.label_count):
            graph.add_node(label)
            if isinstance(node, TDSourceNode):
                sources[label] = node.offset
                offsets[node.offset].append(label)
            elif isinstance(node, TDUnionNode):
                graph.add_edge(node.right, label)
                graph.add_edge(node.left, label)
            elif isinstance(node, TDRangeNode):
                for range_label in range(node.first, node.last + 1):
                    graph.add_edge(range_label, label)
            else:
                raise Exception("Unsupported node type")
        # Merge nodes that correspond to the same offset
        for ns in offsets.values():
            for n in ns[1:]:
                nx.contracted_nodes(graph, ns[0], n, copy=False)

        return graph, sources

    def run(self, args):
        def to_intervals(c: Iterable[int]) -> List[Tuple[int, int]]:
            r: List[Tuple[int, int]] = []
            for b in sorted(list(c)):
                if len(r) > 0 and b <= r[-1][1]:
                    continue
                e = b
                while e + 1 in c:
                    e += 1
                r.append((b, e))
            return r

        def print_intervals(i: Tuple[int, int]) -> str:
            return f"{i[0]} - {i[1]}"

        def clusters(g: nx.DiGraph, s: Dict[int, int]) -> Iterable[Iterable[int]]:
            cs = nx.weakly_connected_components(g)
            cs = map(lambda x: x.intersection(s), cs)
            cs = map(lambda c: map(s.get, c), cs)
            return map(lambda x: sorted(list(x)), cs)
            
        def index_array(g: nx.DiGraph, s: Dict[int, int]) -> List[int]:
            id = [-1] * (max(s.values()) + 1)
            for i, c in enumerate(clusters(g, s)):
                for o in c:
                    id[o] = i
            return id
        
        def graph_and_sources(path: Path) -> Tuple[nx.DiGraph, Dict[int, int]]:
            with open(path, "rb") as file:
                return self.to_graph(TDFile(file))

        if args.match:
            ias = map(graph_and_sources, args.match)
            ias = map(lambda x: index_array(*x), ias)
            m = match(*ias)
            print(f"{args.match[0]} -> {args.match[1]}")
            for k, v in m.mapping.items():
                print(f"{k} -> {v}")
            print(f"cost={m.edit_distance}, similarity={m.similarity}")
        else:
            for c in clusters(*graph_and_sources(args.trace_file)):
                print(list(map(print_intervals, to_intervals(c))))
