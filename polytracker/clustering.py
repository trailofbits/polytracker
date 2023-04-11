"""
The `clusters` command.
"""

import networkx as nx

from tqdm import tqdm
from typing import Tuple, Set, List

from .plugins import Command
from .taint_dag import TDFile, TDSourceNode, TDUnionNode, TDRangeNode


class Clusters(Command):
    name = "clusters"
    help = "clusters input byte offsets based on their interaction"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_TF", type=str, help="the trace file")

    def to_graph(self, f: TDFile) -> Tuple[nx.DiGraph, Set[int]]:
        graph = nx.DiGraph()
        sources = set()
        for label, node in tqdm(enumerate(f.nodes, start=1), total=f.label_count):
            graph.add_node(label)
            if isinstance(node, TDSourceNode):
                sources.add(label)
            elif isinstance(node, TDUnionNode):
                graph.add_edge(node.left, node.right)
            elif isinstance(node, TDRangeNode):
                for range_label in range(node.first, node.last + 1):
                    graph.add_edge(range_label, label)
            else:
                raise Exception("Unsupported node type")
        return graph, sources

    def run(self, args):
        with open(args.POLYTRACKER_TF, "rb") as file:
            graph, sources = self.to_graph(TDFile(file))
            cs = nx.weakly_connected_components(graph)
            cs = map(lambda x: x.intersection(sources), cs)
            cs = filter(lambda x: len(x) > 1, cs)

            def to_intervals(c: Set[int]) -> List[Tuple[int, int]]:
                r: List[Tuple[int, int]] = []
                for b in sorted(list(c)):
                    if len(r) > 0 and b <= r[-1][1]:
                        continue
                    e = b
                    while e + 1 in c:
                        e += 1
                    r.append((b, e))
                return r

            def to_str(b: int, e: int) -> str:
                if b == e:
                    return str(b)
                else:
                    return f"{b} - {e}"

            for c in map(to_intervals, cs):
                print(list(map(lambda x: to_str(*x), c)))
