"""
This module maps input byte offsets to output byte offsets
"""

from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Set, Tuple, Iterator
from tqdm import tqdm

from .plugins import Command
from .taint_dag import TDFile, TDNode, TDRangeNode, TDSourceNode, TDUnionNode


LabelType = int
OffsetType = int
FileOffsetType = Tuple[Path, OffsetType]
CavityType = Tuple[OffsetType, OffsetType]


class InputOutputMapping:
    def __init__(self, f: TDFile):
        self.tdfile: TDFile = f

    def dfs_walk(
        self, label: LabelType, seen: Set[LabelType] = None
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
        for s in tqdm(list(self.tdfile.sinks)):
            for _, n in self.dfs_walk(s.label):
                if isinstance(n, TDSourceNode):
                    sp = self.tdfile.fd_headers[s.fdidx][0]
                    np = self.tdfile.fd_headers[n.idx][0]
                    result[(np, n.offset)].add((sp, s.offset))

        return result

    def marker_to_ranges(self, m: bytearray) -> List[CavityType]:
        ranges = []
        start = None
        for i, v in enumerate(m):
            if v == 0:
                if start is None:
                    start = i
            else:
                if start is not None:
                    ranges.append((start, i))
                    start = None
        if start is not None:
            ranges.append((start, len(m) - 1))
        return ranges

    def file_cavities(self) -> Dict[Path, List[CavityType]]:
        result: Dict[Path, List[CavityType]] = defaultdict(list)
        seen: Set[LabelType] = set()

        for p, h in self.tdfile.fd_headers:
            begin = h.prealloc_label_begin
            end = h.prealloc_label_end
            length = end - begin

            if length < 1:
                continue

            marker = bytearray(length)
            # Initially, mark all source taint that affects control flow
            for i, label in enumerate(range(begin, end)):
                if self.tdfile.decode_node(label).affects_control_flow:
                    marker[i] = 1
            # Now, iterate all source labels in the taint sink. As an optimization, if
            # the taint affects_control_flow, move on. It already spilled into the source
            # taint and was marked above
            for s in tqdm(list(self.tdfile.sinks)):
                sn = self.tdfile.decode_node(s.label)
                if sn.affects_control_flow:
                    continue
                if isinstance(sn, TDSourceNode):
                    marker[sn.offset] = 1
                else:
                    for lbl, n in self.dfs_walk(s.label, seen):
                        if isinstance(n, TDSourceNode):
                            marker[lbl - begin] = 1
                        elif n.affects_control_flow:
                            if isinstance(n, TDUnionNode):
                                seen.add(n.left)
                                seen.add(n.right)
                            elif isinstance(n, TDRangeNode):
                                seen.update(range(n.first, n.last + 1))

            result[Path(p)] = self.marker_to_ranges(marker)

        return result


class MapInputsToOutputs(Command):
    name = "mapping"
    help = "generate a mapping of input byte offsets to output byte offsets"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_TF", type=str, help="the trace file")

    def run(self, args):
        with open(args.POLYTRACKER_TF, "rb") as f:
            print(InputOutputMapping(TDFile(f)).mapping())


def ascii(b: bytes) -> str:
    result = []
    for i in b:
        if i == ord("\\"):
            result.append("\\\\")
        elif i == ord('"'):
            result.append('\\"')
        elif ord(" ") <= i <= ord("~"):
            result.append(chr(i))
        elif i == 0:
            result.append("\\0")
        elif i == ord("\n"):
            result.append("\\n")
        elif i == ord("\t"):
            result.append("\\t")
        elif i == ord("\r"):
            result.append("\\r")
        elif i < 10:
            result.append(f"\\{i}")
        else:
            result.append(f"\\x{i:x}")
    return "".join(result)


class FileCavities(Command):
    name = "cavities"
    help = "finds input byte offsets that do not affect any output byte offsets"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_TF", type=str, help="the trace file")
        parser.add_argument(
            "--print-bytes",
            "-b",
            action="store_true",
            help="print file bytes in and around the cavity",
        )

    def run(self, args):
        def print_cavity(path: Path, begin: LabelType, end: LabelType) -> None:
            print(f"{path},{begin},{end}")

        with open(args.POLYTRACKER_TF, "rb") as f:
            cavities = InputOutputMapping(TDFile(f)).file_cavities()

            if not args.print_bytes:
                for path, cs in cavities.items():
                    for cavity in cs:
                        print_cavity(path, *cavity)
                return

            for path, cs in cavities.items():
                with open(path, "rb") as f:
                    for begin, end in cs:
                        print_cavity(path, begin, end)
                        contents = f.read()
                        before = ascii(contents[max(begin - 10, 0) : begin])
                        after = ascii(contents[end : end + 10])
                        inside = ascii(contents[begin:end])
                        print(f'\t"{before}{inside}{after}"')
                        print(f"\t {' ' * len(before)}{'^' * len(inside)}")
