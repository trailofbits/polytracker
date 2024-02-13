"""
This module maps input byte offsets to output byte offsets
"""

from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set, Tuple
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
        for s in tqdm(list(self.tdfile.sinks)):
            for _, n in self.dfs_walk(s.label):
                if isinstance(n, TDSourceNode):
                    sp = self.tdfile.fd_headers[s.fdidx][0]
                    np = self.tdfile.fd_headers[n.idx][0]
                    result[(np, n.offset)].add((sp, s.offset))

        return result

    def marker_to_ranges(self, m: bytes) -> List[CavityType]:
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
            ranges.append((start, len(m)))
        return ranges

    def file_cavities(self) -> Dict[Path, List[CavityType]]:
        seen: Set[LabelType] = set()
        markers: Dict[int, bytearray] = {}

        # Create the initial marker arrays, one per source file. Each offset in the
        # marker array corresponds to a single source file offset. Iterate over all
        # source taint labels, mark any that affects control flow. If they affect
        # control flow they are not a cavity. This will allow optimizations when
        # iterating over sinks as any taint node that affects control flow will
        # already have all of its source taints affecting control flow, and thus
        # be in the marker array already.
        with tqdm(desc="indexing taint sources", unit="labels", leave=False) as t:
            for source_label in self.tdfile.input_labels():
                t.update(1)
                source_node = self.tdfile.decode_node(source_label)
                assert isinstance(source_node, TDSourceNode)
                source_index = source_node.idx
                source_offset = source_node.offset

                if source_index not in markers:
                    # Attempt to get the size of the file, to prevent reallocation of the markers array.
                    # Use whatever size is greater (size hint will be zero for failures) to allocate the
                    # array.
                    fdheader = self.tdfile.fd_headers[source_index][1]
                    size = (
                        source_offset + 1 if fdheader.invalid_size() else fdheader.size
                    )
                    markers[source_index] = bytearray(size)

                marker = markers[source_index]
                if source_offset >= len(marker):
                    marker = marker.ljust(source_offset + 1, b"\0")
                    markers[source_index] = marker

                if source_node.affects_control_flow:
                    marker[source_offset] = 1

        # Now, iterate all taint labels written to outputs (sinks). Walk them backwards to reach
        # source nodes and mark any source offset contributing to outputs. If a node affects
        # control flow, it can be disregarded as that would already have spilled into the source
        # node (see above).
        for s in tqdm(list(self.tdfile.sinks)):
            sn = self.tdfile.decode_node(s.label)
            if sn.affects_control_flow:
                continue

            # If it is a source node add it (unless it affects control flow as it was already
            # set by the initial sweep).
            if isinstance(sn, TDSourceNode) and not sn.affects_control_flow:
                markers[sn.idx][sn.offset] = 1
            else:
                for lbl, n in self.dfs_walk(s.label, seen):
                    if isinstance(n, TDSourceNode):
                        markers[n.idx][n.offset] = 1
                    elif n.affects_control_flow:
                        if isinstance(n, TDUnionNode):
                            seen.add(n.left)
                            seen.add(n.right)
                        elif isinstance(n, TDRangeNode):
                            seen.update(range(n.first, n.last + 1))

        # Flatten all files by name in case files are opened multiple times
        merged: Dict[Path, bytes] = {}

        for k, v in markers.items():
            fname = self.tdfile.fd_headers[k][0]
            if fname in merged:
                merged[fname] = bytes(a | b for (a, b) in zip(merged[fname], v))
            else:
                merged[fname] = bytes(v)

        # Convert the source index to the source path and marker bit arrays to ranges
        return {k: self.marker_to_ranges(v) for (k, v) in merged.items()}


class MapInputsToOutputs(Command):
    name = "mapping"
    help = "generate a mapping of input byte offsets to output byte offsets"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_TF", type=str, help="the trace file")

    def run(self, args):
        with open(args.POLYTRACKER_TF, "rb") as f:
            # to date, only the labels section is needed to compute the mapping
            # so to speed things up for large tdags, don't read the cflog in!
            tdfile = TDFile(f, cflog=False)
            print(InputOutputMapping(tdfile).mapping())


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
            print(f"input path was: {path}; cavity: {begin},{end}")

        with open(args.POLYTRACKER_TF, "rb") as f:
            # to date, only the labels section is needed to compute cavities
            # so to speed things up for large tdags, don't read the cflog in!
            tdfile = TDFile(f, cflog=False)
            cavities = InputOutputMapping(tdfile).file_cavities()

            if not args.print_bytes:
                for path, cs in cavities.items():
                    for cavity in cs:
                        print_cavity(path, *cavity)
                return

            for path, cs in cavities.items():
                with open(path, "rb") as f:
                    contents = f.read()
                    for begin, end in cs:
                        print_cavity(path, begin, end)
                        before = ascii(contents[max(begin - 10, 0) : begin])
                        after = ascii(contents[end : end + 10])
                        inside = ascii(contents[begin:end])
                        print(f'\t"{before}{inside}{after}"')
                        print(f"\t {' ' * len(before)}{'^' * len(inside)}")
