from argparse import ArgumentParser, Namespace
from collections import defaultdict
from io import StringIO
import os
from typing import Dict, FrozenSet, Iterable, Iterator, Optional, TextIO, Tuple

from intervaltree import Interval, IntervalTree
from tqdm import tqdm

from .plugins import Command
from .tracing import Function, Input, ProgramTrace, TaintDiff, TaintedRegion
from .visualizations import file_diff, Image, temporal_animation


def print_file_context(
    output: TextIO,
    path: str,
    offset: int,
    length: int,
    num_bytes_context: int = 32,
    max_highlight_bytes=32,
    indent: str = "",
):
    if length > max_highlight_bytes:
        extra_bytes = length - max_highlight_bytes
        length = max_highlight_bytes
    else:
        extra_bytes = 0
    extra_context_bytes = num_bytes_context
    extra_context_before = extra_context_bytes // 2
    if extra_bytes > 0:
        extra_context_bytes = extra_context_before
    if offset - extra_context_before < 0:
        extra_context_before = offset
    start = offset - extra_context_before
    output.write(f"{indent}@{offset}\n{indent}")
    with open(path, "rb") as s:
        s.seek(start)
        data = s.read(length + extra_context_bytes)
        highlight_start = -1
        highlight_length = -1
        written = 0
        for i, b in enumerate(data):
            if b == ord("\n"):
                to_write = "\\n"
            elif b == ord("\r"):
                to_write = "\\r"
            elif b == ord("\\"):
                to_write = "\\\\"
            elif b == ord("\t"):
                to_write = "\\t"
            elif ord(" ") <= b <= ord("~"):
                to_write = chr(b)
            else:
                to_write = f"\\x{b:02x}"
            if i == extra_context_before:
                highlight_start = written
            if i == extra_context_before + length:
                highlight_length = written - highlight_start
            written += len(to_write)
            output.write(to_write)
        if extra_bytes:
            output.write(
                f" [ … plus {extra_bytes} additional byte{['', 's'][extra_bytes > 1]} … ]"
            )
        output.write("\n")
        if highlight_length < 0 <= highlight_start:
            highlight_length = written - highlight_start
        if highlight_length > 0:
            output.write(f"{indent}{' ' * highlight_start}{'^' * highlight_length}\n")


class ControlFlowDiff:
    def __init__(self, trace1: ProgramTrace, trace2: ProgramTrace, function_name: str):
        self.trace1: ProgramTrace = trace1
        self.trace2: ProgramTrace = trace2
        self.func: str = function_name
        self._first_function_with_different_control_flow: Optional[str] = None
        self._diffed: bool = False

    @property
    def first_function_with_different_control_flow(self) -> Optional[str]:
        if not self._diffed:
            self._diff()
        return self._first_function_with_different_control_flow

    def _diff(self):
        if self._diffed:
            return
        self._diffed = True
        if not self.trace1.has_function(self.func) or not self.trace2.has_function(self.func):
            return
        func1 = self.trace1.get_function(self.func)
        func2 = self.trace2.get_function(self.func)
        doms1 = self.trace1.function_cfg.dominator_forest
        doms2 = self.trace2.function_cfg.dominator_forest

        ancestors1 = doms1.ancestors(func1)
        ancestors2 = doms2.ancestors(func2)

        ancestors1 &= ancestors2
        ancestors2 &= ancestors1

        if not ancestors1 or not ancestors2:
            # they have no ancestors in common
            return

        for a1, a2 in zip(ancestors1, ancestors2):
            if a1.name != a2.name:
                continue
            if a1.taints() != a2.taints():
                self._first_function_with_different_control_flow = a1.name
                break

    def __bool__(self):
        return self.first_function_with_different_control_flow is not None


class TraceDiff:
    def __init__(self, trace1: ProgramTrace, trace2: ProgramTrace):
        self.trace1: ProgramTrace = trace1
        self.trace2: ProgramTrace = trace2
        self._functions_only_in_first: Optional[FrozenSet[Function]] = None
        self._functions_only_in_second: Optional[FrozenSet[Function]] = None
        self._bytes_only_in_first: Optional[Dict[Input, IntervalTree]] = None
        self._bytes_only_in_second: Optional[Dict[Input, IntervalTree]] = None
        self._first_intervals: Dict[Input, IntervalTree] = defaultdict(IntervalTree)
        self._second_intervals: Dict[Input, IntervalTree] = defaultdict(IntervalTree)

    @property
    def first_intervals(self) -> Dict[Input, IntervalTree]:
        self._diff_bytes()
        return self._first_intervals

    @property
    def second_intervals(self) -> Dict[Input, IntervalTree]:
        self._diff_bytes()
        return self._second_intervals

    @property
    def functions_only_in_first(self) -> FrozenSet[Function]:
        if self._functions_only_in_first is None:
            self._diff_functions()
        return self._functions_only_in_first  # type: ignore

    @property
    def functions_only_in_second(self) -> FrozenSet[Function]:
        if self._functions_only_in_second is None:
            self._diff_functions()
        return self._functions_only_in_second  # type: ignore

    @property
    def functions_in_both(self) -> Iterator[Tuple[str, TaintDiff]]:
        for fname in {
            func.name
            for func in self.trace1.functions
            if func.name
            not in {
                f.name
                for f in (self.functions_only_in_first | self.functions_only_in_second)
            }
        }:
            yield fname, self.trace1.get_function(fname).taints().diff(self.trace2.get_function(fname).taints())

    def _diff_functions(self):
        if self._functions_only_in_first is None:
            first_funcs = frozenset(self.trace1.functions)
            second_funcs = frozenset(self.trace2.functions)
            self._functions_only_in_first = first_funcs - second_funcs
            self._functions_only_in_second = second_funcs - first_funcs

    def _diff_bytes(self):
        if self._bytes_only_in_first is not None:
            return
        # TODO: Instead of looking at what functions touched, just look at the bytes in the canonical mapping!
        with tqdm(
            desc="Diffing tainted byte regions", leave=False, unit=" trace", total=2
        ) as t:
            for func in tqdm(
                self.trace1.functions,
                desc="Trace 1",
                unit=" functions",
                leave=False,
            ):
                for region in func.taints().regions():
                    self._first_intervals[region.source].add(Interval(region.offset, region.offset + region.length))
            for interval in self._first_intervals.values():
                interval.merge_overlaps()
            t.update(1)
            for func in tqdm(
                self.trace2.functions,
                desc="Trace 2",
                unit=" functions",
                leave=False,
            ):
                for region in func.taints().regions():
                    self._second_intervals[region.source].add(Interval(region.offset, region.offset + region.length))
            for interval in self._second_intervals.values():
                interval.merge_overlaps()
            t.update(2)
            self._bytes_only_in_first = {}
            self._bytes_only_in_second = {}
            for source in self._first_intervals.keys() & self._second_intervals.keys():
                # shared sources
                self._bytes_only_in_first[source] = self._first_intervals[source].copy()
                for interval in tqdm(
                    self._second_intervals[source],
                    desc="Removing Trace 1 Overlap",
                    unit=" intervals",
                    leave=False,
                ):
                    self._bytes_only_in_first[source].remove_overlap(
                        interval.begin, interval.end
                    )
                self._bytes_only_in_second[source] = self._second_intervals[
                    source
                ].copy()
                for interval in tqdm(
                    self._first_intervals[source],
                    desc="Removing Trace 2 Overlap",
                    unit=" intervals",
                    leave=False,
                ):
                    self._bytes_only_in_second[source].remove_overlap(
                        interval.begin, interval.end
                    )
                assert (
                    len(
                        self._bytes_only_in_first[source]
                        & self._bytes_only_in_second[source]
                    )
                    == 0
                )
            for source in self._first_intervals.keys() - self._second_intervals.keys():
                # sources only in first
                self._bytes_only_in_first[source] = self._first_intervals[source]
            for source in self._second_intervals.keys() - self._first_intervals.keys():
                # sources only in second
                self._bytes_only_in_second[source] = self._second_intervals[source]

    @property
    def input_chunks_only_in_first(self) -> Iterator[TaintedRegion]:
        if self._bytes_only_in_first is None:
            self._diff_bytes()
        for source, tree in self._bytes_only_in_first.items():  # type: ignore
            for interval in sorted(tree):
                yield TaintedRegion(source=source, offset=interval.begin, length=interval.end - interval.begin)

    @property
    def input_chunks_only_in_second(self) -> Iterator[TaintedRegion]:
        if self._bytes_only_in_second is None:
            self._diff_bytes()
        for source, tree in self._bytes_only_in_second.items():  # type: ignore
            for interval in sorted(tree):
                yield TaintedRegion(source=source, offset=interval.begin, length=interval.end - interval.begin)

    @property
    def has_input_chunks_only_in_first(self) -> bool:
        if self._bytes_only_in_first is None:
            self._diff_bytes()
        return any(len(tree) > 0 for tree in self._bytes_only_in_first.values())  # type: ignore

    @property
    def has_input_chunks_only_in_second(self) -> bool:
        if self._bytes_only_in_second is None:
            self._diff_bytes()
        return any(len(tree) > 0 for tree in self._bytes_only_in_second.values())  # type: ignore

    def to_image(self) -> Image:
        self._diff_bytes()
        sources = set(self.trace1.inputs) | set(self.trace2.inputs)
        for source in sources:
            num_bytes = source.size
            return file_diff(
                num_bytes,
                lambda offset: source in self._first_intervals and self._first_intervals[source].overlaps(offset),
                lambda offset: source in self._second_intervals and self._second_intervals[source].overlaps(offset),
            )

    def __bool__(self):
        return bool(self.functions_only_in_first) or bool(self.functions_only_in_second)

    def __str__(self):
        status = StringIO()

        def print_chunk_info(chunks: Iterable[TaintedRegion], indent: str = "\t"):
            for r in chunks:
                if os.path.exists(r.source.path):
                    print_file_context(
                        status,
                        path=r.source.path,
                        offset=r.offset,
                        length=r.length,
                        indent=indent,
                    )
                else:
                    status.write(f"\tTouched {r.length} bytes at offset {r.offset}\n")

        if self.has_input_chunks_only_in_first:
            status.write(
                "The reference trace touched the following byte regions that were not touched by the diffed "
                "trace:\n"
            )
            for region in self.input_chunks_only_in_first:
                print_chunk_info((region,))
                for func in self.trace1.functions:
                    if IntervalTree.from_tuples(
                        (r.offset, r.offset + r.length) for r in func.taints().regions() if r.source == region.source
                    ).overlaps(region.offset, region.offset + region.length):
                        # find the control flows that could have caused the diff
                        cfd = ControlFlowDiff(self.trace1, self.trace2, func.name)
                        if cfd:
                            different_function = cfd.first_function_with_different_control_flow
                            function_diff = self.trace1.get_function(different_function).taints().diff(
                                self.trace2.get_function(different_function).taints()
                            )
                            if not bool(function_diff):
                                continue
                            status.write(
                                f"\tFunction {different_function!s} could contain the control flow that led "
                                "to this differential\n"
                            )
                            if function_diff.bytes_only_in_first:
                                status.write(
                                    "\t\tHere are the bytes that affected control flow only in the reference "
                                    "trace:\n"
                                )
                                print_chunk_info(
                                    function_diff.regions_only_in_first,
                                    indent="\t\t\t",
                                )
                            if function_diff.bytes_only_in_second:
                                status.write(
                                    "\t\tHere are the bytes that affected control flow only in the differed "
                                    "trace:\n"
                                )
                                print_chunk_info(
                                    function_diff.regions_only_in_second,
                                    indent="\t\t\t",
                                )

        if self.has_input_chunks_only_in_second:
            status.write(
                "The diffed trace touched the following byte regions that were not touched by the reference "
                "trace:\n"
            )
            for region in self.input_chunks_only_in_second:
                print_chunk_info((region,))
                for func in self.trace2.functions:
                    if IntervalTree.from_tuples(
                        (r.offset, r.offset + r.length) for r in func.taints().regions() if r.source == region.source
                    ).overlaps(region.offset, region.offset + region.length):
                        # find the control flows that could have caused the diff
                        cfd = ControlFlowDiff(self.trace1, self.trace2, func.name)
                        if cfd:
                            different_function = cfd.first_function_with_different_control_flow
                            function_diff = self.trace1.get_function(different_function).taints().diff(
                                self.trace2.get_function(different_function).taints()
                            )
                            if not bool(function_diff):
                                continue
                            status.write(
                                f"\tFunction {different_function!s} could contain the control flow that led "
                                "to this differential\n"
                            )
                            if function_diff.bytes_only_in_first:
                                status.write(
                                    "\t\tHere are the bytes that affected control flow only in the reference "
                                    "trace:\n"
                                )
                                print_chunk_info(
                                    function_diff.regions_only_in_first,
                                    indent="\t\t\t",
                                )
                            if function_diff.bytes_only_in_first:
                                status.write(
                                    "\t\tHere are the bytes that affected control flow only in the differed "
                                    "trace:\n"
                                )
                                print_chunk_info(
                                    function_diff.regions_only_in_second,
                                    indent="\t\t\t",
                                )

        if (
            not self.has_input_chunks_only_in_first
            and not self.has_input_chunks_only_in_second
        ):
            status.write("Both traces consumed the exact same input byte regions\n")

        for func in self.functions_only_in_first:
            status.write(
                f"Function {func!s} was called in the reference trace but not in the diffed trace\n"
            )
            print_chunk_info(func.taints().regions())
        for func in self.functions_only_in_second:
            status.write(
                f"Function {func!s} was called in the diffed trace but not in the reference trace\n"
            )
            print_chunk_info(func.taints().regions())
        for fname, func in self.functions_in_both:
            if func:
                # different input bytes affected control flow
                if func.bytes_only_in_first:
                    status.write(
                        f"Function {fname!s} in the reference trace had the following bytes that tainted "
                        "control flow which did not affect control flow in the diffed trace:\n"
                    )
                    print_chunk_info(func.regions_only_in_first)
                if func.bytes_only_in_second:
                    status.write(
                        f"Function {fname!s} in the diffed trace had the following bytes that tainted "
                        "control flow which did not affect control flow in the reference trace:\n"
                    )
                    print_chunk_info(func.regions_only_in_second)

        if not self:
            status.write(f"Traces do not differ")
        return status.getvalue()


class TraceDiffCommand(Command):
    name = "diff"
    help = "compute a diff of two program traces"

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument(
            "trace1", type=str, help="the output database from the first trace"
        )
        parser.add_argument(
            "trace2", type=str, help="the output database from the second trace"
        )
        parser.add_argument(
            "--image",
            type=str,
            default=None,
            help="path to optionally output a visualization of the" "diff",
        )

    def run(self, args: Namespace):
        from . import PolyTrackerTrace
        trace1 = PolyTrackerTrace.load(args.trace1)
        trace2 = PolyTrackerTrace.load(args.trace2)
        diff = TraceDiff(trace1, trace2)
        print(str(diff))
        if args.image is not None:
            diff.to_image().save(args.image)


class TemporalVisualization(Command):
    name = "temporal"
    help = "generate an animation of the file accesses in a runtime trace"

    def __init_arguments__(self, parser):
        parser.add_argument(
            "POLYTRACKER_DB", type=str, help="the trace database"
        )
        parser.add_argument(
            "OUTPUT_GIF_PATH", type=str, help="the path to which to save the animation"
        )

    def run(self, args):
        from . import PolyTrackerTrace
        trace = PolyTrackerTrace.load(args.POLYTRACKER_DB)
        temporal_animation(args.OUTPUT_GIF_PATH, trace)
