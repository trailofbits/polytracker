#!/usr/bin/python

from collections import defaultdict
from pathlib import Path
from polytracker.taint_dag import TDFile, TDNode, TDSourceNode, TDUnionNode, TDRangeNode
from typing import Optional, Set, Iterator, Tuple, Dict

LabelType = int
OffsetType = int
FileOffsetType = Tuple[Path, OffsetType]
CavityType = Tuple[OffsetType, OffsetType]


class OutputInputMapping:
    def __init__(self, f: TDFile):
        self.tdfile: TDFile = f

    def dfs_walk(
        self, label: LabelType, seen: Optional[Set[LabelType]] = None
    ) -> Iterator[Tuple[LabelType, TDNode]]:
        if seen is None:
            seen = set()

        stack = [label]
        while stack:
            lbl = stack.pop()

            if lbl in seen:
                continue

            seen.add(lbl)

            n = self.tdfile.decode_node(lbl)

            yield (lbl, n)

            if isinstance(n, TDSourceNode):
                continue

            elif isinstance(n, TDUnionNode):
                stack.append(n.left)
                stack.append(n.right)

            elif isinstance(n, TDRangeNode):
                stack.extend(range(n.first, n.last + 1))

    def mapping(self) -> Dict[FileOffsetType, Set[FileOffsetType]]:
        result: Dict[FileOffsetType, Set[FileOffsetType]] = defaultdict(set)
        for s in list(self.tdfile.sinks):
            for _, n in self.dfs_walk(s.label):
                if isinstance(n, TDSourceNode):
                    sp = self.tdfile.fd_headers[s.fdidx][0]
                    np = self.tdfile.fd_headers[n.idx][0]
                    result[(sp, s.offset)].add((np, n.offset))

        return result
