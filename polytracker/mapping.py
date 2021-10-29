"""
This module maps input byte offsets to output byte offsets
"""

from collections import defaultdict
from typing import Dict, Set

from tqdm import tqdm

from . import PolyTrackerTrace
from .plugins import Command
from .tracing import ByteOffset


def map_inputs_to_outputs(trace: PolyTrackerTrace) -> Dict[ByteOffset, Set[ByteOffset]]:
    inputs = {i.uid: i for i in trace.inputs}

    ret: Dict[ByteOffset, Set[ByteOffset]] = defaultdict(set)

    for output_taint in tqdm(trace.output_taints, unit=" output taints", leave=False):
        written_to = inputs[output_taint.input_id]
        output_byte_offset = ByteOffset(source=written_to, offset=output_taint.offset)
        for byte_offset in output_taint.taints():
            ret[byte_offset].add(output_byte_offset)

    return ret


class MapInputsToOutputs(Command):
    name = "mapping"
    help = "generate a mapping of input byte offsets to output byte offsets"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_DB", type=str, help="the trace database")

    def run(self, args):
        from . import PolyTrackerTrace

        mapping = map_inputs_to_outputs(PolyTrackerTrace.load(args.POLYTRACKER_DB))

        print(mapping)
