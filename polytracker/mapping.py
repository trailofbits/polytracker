"""
This module maps input byte offsets to output byte offsets
"""

from collections import defaultdict
from typing import Dict, Set

from . import PolyTrackerTrace
from .plugins import Command
from .tracing import ByteOffset


def map_inputs_to_outputs(trace: PolyTrackerTrace) -> Dict[ByteOffset, Set[ByteOffset]]:
    inputs = {i.uid: i for i in trace.inputs}

    ret: Dict[ByteOffset, Set[ByteOffset]] = defaultdict(set)

    for output_taint in trace.output_taints:
        for taint in output_taint.taints():
            for byte_offset in taint:
                ret[byte_offset].add(inputs[output_taint.input_id])

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
