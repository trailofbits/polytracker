"""
This module maps input byte offsets to output byte offsets
"""

from collections import defaultdict
from typing import Dict, List, Iterator, Set

from intervaltree import Interval, IntervalTree
from tqdm import tqdm

from . import PolyTrackerTrace
from .inputs import Input
from .plugins import Command
from .tracing import ByteOffset, TaintedRegion
from .taint_forest import TaintForestNode

# from .tracing import TaintOutput, Taints


class InputOutputMapping:
    def __init__(self, trace: PolyTrackerTrace):
        self.trace: PolyTrackerTrace = trace
        # self.inputs = {i.uid: i for i in trace.inputs}
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

    # TODO(surovic): unused
    # def read_from(self, output: TaintOutput) -> Set[ByteOffset]:
    #     written_to = self.inputs[output.source.uid]
    #     output_byte_offset = ByteOffset(source=written_to, offset=output.offset)
    #     ret: Set[ByteOffset] = set()
    #     for byte_offset in output.taints():
    #         self._mapping[byte_offset].add(output_byte_offset)
    #         ret.add(byte_offset)
    #     return ret

    def written_input_bytes(self) -> Iterator[ByteOffset]:
        """Yields all of the input byte offsets from input files that are written to an output file"""
        sink_nodes: List[TaintForestNode] = []
        for t in self.trace.output_taints:
            sink_nodes.append(self.trace.taint_forest.get_node(t.label))
        yield from self.trace.taints(sink_nodes)

    def file_cavities(self) -> Iterator[TaintedRegion]:
        sources: Dict[Input, IntervalTree] = defaultdict(IntervalTree)
        for offset in self.written_input_bytes():
            sources[offset.source].addi(offset.offset, offset.offset + offset.length)
        # also add any input bytes that affected control flow:
        for offset in self.trace.inputs_affecting_control_flow():
            sources[offset.source].addi(offset.offset, offset.offset + offset.length)
        for source, tree in sources.items():
            unused_bytes = IntervalTree([Interval(0, source.size)])
            for interval in tree:
                unused_bytes.chop(interval.begin, interval.end)
            for interval in sorted(unused_bytes):
                yield TaintedRegion(
                    source=source,
                    offset=interval.begin,
                    length=interval.end - interval.begin,
                )


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
    help = "finds input byte offsets that were never written to an output file"

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
                f"{cavity.source.path}\t{cavity.offset}–{cavity.offset + cavity.length - 1}"
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
