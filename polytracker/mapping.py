"""
This module maps input byte offsets to output byte offsets
"""

from collections import defaultdict
from typing import Dict, Iterator, Set

from intervaltree import Interval, IntervalTree
from tqdm import tqdm

from . import PolyTrackerTrace
from .inputs import Input
from .plugins import Command
from .tracing import ByteOffset, TaintOutput, TaintedRegion


class InputOutputMapping:
    def __init__(self, trace: PolyTrackerTrace):
        self.trace: PolyTrackerTrace = trace
        self.inputs = {i.uid: i for i in trace.inputs}
        self._mapping: Dict[ByteOffset, Set[ByteOffset]] = defaultdict(set)
        self._mapping_is_complete: bool = False

    @property
    def mapping(self) -> Dict[ByteOffset, Set[ByteOffset]]:
        if self._mapping_is_complete:
            return self._mapping

        for output_taint in tqdm(self.trace.output_taints, unit=" output taints", leave=False):
            written_to = self.inputs[output_taint.input_id]
            output_byte_offset = ByteOffset(source=written_to, offset=output_taint.offset)
            for byte_offset in output_taint.taints():
                self._mapping[byte_offset].add(output_byte_offset)

        self._mapping_is_complete = True

        return self._mapping

    def read_from(self, output: TaintOutput) -> Set[ByteOffset]:
        written_to = self.inputs[output.input_id]
        output_byte_offset = ByteOffset(source=written_to, offset=output.offset)
        ret: Set[ByteOffset] = set()
        for byte_offset in output.taints():
            self._mapping[byte_offset].add(output_byte_offset)
            ret.add(byte_offset)
        return ret

    def written_input_bytes(self) -> Iterator[ByteOffset]:
        """Yields all of the input byte offsets from input files that are written to an output file"""
        output_labels = {
            output_taint.label
            for output_taint in tqdm(self.trace.output_taints, unit=" output taints", leave=False)
        }
        yielded: Set[ByteOffset] = set()
        for node in tqdm(self.trace.taint_forest, desc="searching taint forest", unit=" nodes", leave=False):
            # this is guaranteed to iterate over the nodes in order of decreasing label
            if node.label in output_labels:
                if node.is_canonical():
                    # this was written!
                    offset = self.trace.file_offset(node)
                    if offset not in yielded:
                        yield offset
                        yielded.add(offset)
                else:
                    if node.parent_one is not None:
                        output_labels.add(node.parent_one.label)
                    if node.parent_two is not None:
                        output_labels.add(node.parent_two.label)

    def file_cavities(self) -> Iterator[TaintedRegion]:
        sources: Dict[Input, IntervalTree] = defaultdict(IntervalTree)
        for offset in self.written_input_bytes():
            sources[offset.source].addi(offset.offset, offset.offset + offset.length)
        for source, tree in sources.items():
            unused_bytes = IntervalTree([Interval(0, source.size)])
            for interval in tree:
                unused_bytes.chop(interval.begin, interval.end)
            for interval in sorted(unused_bytes):
                yield TaintedRegion(source=source, offset=interval.begin, length=interval.end - interval.begin)


class MapInputsToOutputs(Command):
    name = "mapping"
    help = "generate a mapping of input byte offsets to output byte offsets"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_DB", type=str, help="the trace database")

    def run(self, args):
        from . import PolyTrackerTrace

        mapping = InputOutputMapping(PolyTrackerTrace.load(args.POLYTRACKER_DB)).mapping

        print(mapping)


class FileCavities(Command):
    name = "cavities"
    help = "finds input byte offsets that were never written to an output file"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_DB", type=str, help="the trace database")

    def run(self, args):
        from . import PolyTrackerTrace

        for cavity in InputOutputMapping(PolyTrackerTrace.load(args.POLYTRACKER_DB)).file_cavities():
            print(f"{cavity.source.path}\t{cavity.offset}–{cavity.offset + cavity.length - 1}")
