#!/usr/bin/env python3

import heapq
from tqdm import tqdm
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from polytracker import taint_dag, TDFile


class CachingTDAGTraverser:
    def __init__(self, tdag: TDFile, max_size: Optional[int] = None):
        self.tdag: TDFile = tdag
        self.max_size: Optional[int] = max_size
        self._cache: Dict[int, FrozenSet[taint_dag.TDSourceNode]] = {}
        self._age: List[Tuple[int, int]] = []
        self._insertions: int = 0

    def _cache_add(self, label: int, source_nodes: FrozenSet[taint_dag.TDSourceNode]):
        if self.max_size is not None:
            while len(self._cache) > self.max_size:
                _, oldest_label = heapq.heappop(self._age)
                del self._cache[oldest_label]
            self._insertions += 1
            heapq.heappush(self._age, (self._insertions, label))
        self._cache[label] = source_nodes

    def __getitem__(self, item: int) -> FrozenSet[taint_dag.TDSourceNode]:
        stack: List[Tuple[int, int, List[FrozenSet]]] = [(item, -1, [])]
        cache_hits = 0
        with tqdm(
            desc="finding canonical taints",
            unit="labels",
            leave=False,
            delay=2.0,
            total=1,
        ) as t:
            while True:
                label, num_parents, ancestor_sets = stack[-1]

                if label in self._cache:
                    stack.pop()
                    t.update(1)
                    cached = self._cache[label]
                    cache_hits += 1
                    if not stack:
                        # we are done
                        # print(f"Cache hits for {item}: {cache_hits}")
                        return cached
                    stack[-1][2].append(cached)
                    continue
                elif num_parents == len(ancestor_sets):
                    ancestors = frozenset.union(*ancestor_sets)
                    self._cache_add(label, ancestors)
                    continue

                node: taint_dag.TDNode = self.tdag.decode_node(label)
                if isinstance(node, taint_dag.TDSourceNode):
                    self._cache_add(label, frozenset((node,)))
                    continue
                elif isinstance(node, taint_dag.TDUnionNode):
                    if num_parents < 0:
                        stack[-1] = (label, 2, [])
                        stack.append((node.left, -1, []))
                    else:
                        stack.append((node.right, -1, []))
                    t.total += 1
                    t.refresh()
                elif isinstance(node, taint_dag.TDRangeNode):
                    if num_parents < 0:
                        stack[-1] = (label, node.last - node.first + 1, [])
                    else:
                        stack.append((node.first + len(ancestor_sets), -1, []))
                        t.total += 1
                        t.refresh()
