"""
The `clusters` command.
"""

import networkx as nx

from scipy import sparse
from tqdm import tqdm
from typing import Tuple, Set

from .plugins import Command
from .taint_dag import TDFile, TDSourceNode, TDUnionNode, TDRangeNode


class Clusters(Command):
    name = "clusters"
    help = "clusters input byte offsets based on their interaction"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_TF", type=str, help="the trace file")

    def to_graph(self, f: TDFile) -> Tuple[nx.DiGraph, Set[int]]:
        graph = nx.DiGraph()
        # sources = set()
        for label, node in tqdm(enumerate(f.nodes, start=1), total=f.label_count):
            graph.add_node(label)
            if isinstance(node, TDSourceNode):
                # sources.add(label)
                pass
            elif isinstance(node, TDUnionNode):
                graph.add_edge(node.left, node.right)
            elif isinstance(node, TDRangeNode):
                for range_label in range(node.first, node.last + 1):
                    graph.add_edge(range_label, label)
            else:
                raise Exception("Unsupported node type")
        # return graph, sources
        return graph

    def run(self, args):
        with open(args.POLYTRACKER_TF, "rb") as f:
            # g, s = self.to_graph(TDFile(f))
            # g = self.to_graph(TDFile(f))
            # sparse.save_npz("graph", nx.to_scipy_sparse_array(g, dtype='I'))
            g = nx.DiGraph(sparse.load_npz("graph.npz"))
            print(len(g))
            # for c in nx.strongly_connected_components(g):
            #     if len(c) > 1:
            #         print(c)
