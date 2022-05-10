"""
This module maps input byte offsets to output byte offsets
"""

from collections import defaultdict
from typing import Dict, List, Set, Tuple
from tqdm import tqdm

from . import PolyTrackerTrace
from .plugins import Command
from .tracing import ByteOffset
from .taint_dag import TDNode, TDRangeNode, TDSourceNode, TDUnionNode


class InputOutputMapping:
    def __init__(self, trace: PolyTrackerTrace):
        self.trace: PolyTrackerTrace = trace
        self._mapping: Dict[ByteOffset, Set[ByteOffset]] = defaultdict(set)
        self._mapping_is_complete: bool = False

    @property
    def mapping(self) -> Dict[ByteOffset, Set[ByteOffset]]:
        if self._mapping_is_complete:
            return self._mapping

        for output_taint in tqdm(
            self.trace.output_taints, unit=" output taints", leave=False
        ):
            inputs = {i.uid: i for i in self.trace.inputs}
            written_to = inputs[output_taint.input_id]
            output_byte_offset = ByteOffset(
                source=written_to, offset=output_taint.offset
            )
            for byte_offset in output_taint.get_taints():
                self._mapping[byte_offset].add(output_byte_offset)

        self._mapping_is_complete = True

        return self._mapping

    def marker_to_ranges(self, m: bytearray) -> List[Tuple[int, int]]:
        ranges = []
        start = None
        for i, v in enumerate(m):
            if v == 0:
                if start is None:
                    start = i
            if v == 1:
                if start is not None:
                    ranges.append((start, i))
                    start = None
        if start is not None:
            ranges.append((start, len(m) - 1))
        return ranges

    def file_cavities(self) -> List[Tuple[str, int, int]]:
        tdfile = self.trace.tdfile
        seen: Set[int] = set()

        def source_labels_not_affecting_cf(label: int) -> int:
            stack = [label]
            while len(stack) > 0:
                lbl = stack.pop()

                if lbl in seen:
                    continue
                
                seen.add(lbl)

                n = tdfile.decode_node(lbl)

                if n.affects_control_flow:
                    continue

                if isinstance(n, TDSourceNode):
                    yield lbl

                elif isinstance(n, TDUnionNode):
                    nl = tdfile.decode_node(n.left)
                    if not nl.affects_control_flow:
                        if isinstance(nl, TDSourceNode):
                            yield n.left
                        else:
                            stack.append(n.left)

                    nr = tdfile.decode_node(n.right)
                    if not nr.affects_control_flow:
                        if isinstance(nr, TDSourceNode):
                            yield n.right
                        else:
                            stack.append(n.right)

                elif isinstance(n, TDRangeNode):
                    for rl in range(n.first, n.last + 1):
                        # NOTE: One could skip decoding here, but then we could end up with really long ranges
                        # being added the labels that really does nothing except cause overhead...
                        rn = tdfile.decode_node(rl)
                        if rn.affects_control_flow:
                            continue
                        if isinstance(rn, TDSourceNode):
                            yield rl
                        else:
                            stack.append(rl)

        result: List[Tuple[str, int, int]] = []

        for p, h in tdfile.fd_headers:
            begin = h.prealloc_label_begin
            end = h.prealloc_label_end
            length = end - begin

            if length < 1:
                continue

            marker = bytearray(length)
            # Initially, mark all source taint that affects control flow
            for i, label in enumerate(range(begin, end)):
                if tdfile.decode_node(label).affects_control_flow:
                    marker[i] = 1
            # Now, iterate all source labels in the taint sink. As an optimization, if
            # the taint affects_control_flow, move one. It already spilled into the source
            # taint and was marked above
            for sink in tqdm(list(tdfile.sinks)):
                n = tdfile.decode_node(sink.label)
                if n.affects_control_flow:
                    continue
                if isinstance(n, TDSourceNode):
                    marker[n.offset] = 1
                else:
                    for source in source_labels_not_affecting_cf(sink.label):
                        marker[source - begin] = 1

            for cavity in self.marker_to_ranges(marker):
                result.append((p,) + cavity)

        return result


class MapInputsToOutputs(Command):
    name = "mapping"
    help = "generate a mapping of input byte offsets to output byte offsets"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_DB", type=str, help="the trace database")

    def run(self, args):
        mapping = InputOutputMapping(PolyTrackerTrace.load(args.POLYTRACKER_DB)).mapping

        print(mapping)


def bytes_to_ascii(b: bytes) -> str:
    ret = []
    for i in b:
        if i == ord("\\"):
            ret.append("\\\\")
        elif i == ord('"'):
            ret.append('\\"')
        elif ord(" ") <= i <= ord("~"):
            ret.append(chr(i))
        elif i == 0:
            ret.append("\\0")
        elif i == ord("\n"):
            ret.append("\\n")
        elif i == ord("\t"):
            ret.append("\\t")
        elif i == ord("\r"):
            ret.append("\\r")
        elif i < 10:
            ret.append(f"\\{i}")
        else:
            ret.append(f"\\x{i:x}")
    return "".join(ret)


class FileCavities(Command):
    name = "cavities"
    help = "finds input byte offsets that do not affect any output byte offsets"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_DB", type=str, help="the trace database")
        parser.add_argument(
            "--print-context",
            "-c",
            action="store_true",
            help="print the context for each file cavity",
        )

    def run(self, args):
        for cavity in InputOutputMapping(
            PolyTrackerTrace.load(args.POLYTRACKER_DB)
        ).file_cavities():
            print(
                f"{cavity.source.path}\t{cavity.offset} - {cavity.offset + cavity.length - 1}"
            )
            if args.print_context:
                content = cavity.source.content
                if content:
                    bytes_before = bytes_to_ascii(
                        content[max(cavity.offset - 10, 0) : cavity.offset]
                    )
                    bytes_after = bytes_to_ascii(
                        content[
                            cavity.offset
                            + cavity.length : cavity.offset
                            + cavity.length
                            + 10
                        ]
                    )
                    cavity_content = bytes_to_ascii(
                        content[cavity.offset : cavity.offset + cavity.length]
                    )
                    print(f'\t"{bytes_before}{cavity_content}{bytes_after}"')
                    print(f"\t {' ' * len(bytes_before)}{'^' * len(cavity_content)}")
