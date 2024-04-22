#!/usr/bin/env python3

from functools import partialmethod
import heapq
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple

import cxxfilt
from graphtage import (
    dataclasses,
    GraphtageFormatter,
    Insert,
    IntegerNode,
    LeafNode,
    ListNode,
    Match,
    Remove,
    Replace,
    StringNode,
)
import functools
import graphtage.printer as printer_module
from graphtage.sequences import SequenceEdit
import itertools
from rich.console import Console
from rich.table import Table
from rich.text import Text
from tqdm import tqdm

from polytracker import taint_dag, TDFile
from polytracker.mapping import CavityType, InputOutputMapping


tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)


class CallStackEntry(LeafNode):
    def __init__(self, func: str):
        super().__init__(func)
        self.func: str = func

    def edits(self, node):
        if isinstance(node, LeafNode) and node.object == self.object:
            return Match(self, node, 0)
        else:
            return Replace(self, node)


class CFLogEntry(dataclasses.DataClassNode):
    """Represents a single entry in the TDAG CFLOG (control flow log) section."""

    input_bytes_node: ListNode
    callstack_node: ListNode
    is_cavity: bool

    def __init__(self, input_bytes: Iterable[int], callstack: Iterable[str]):
        input_bytes = tuple(sorted(set(input_bytes)))
        callstack = tuple(callstack)
        super().__init__(
            input_bytes_node=ListNode((IntegerNode(i) for i in input_bytes)),
            callstack_node=ListNode((CallStackEntry(c) for c in callstack)),
        )
        self.input_bytes: Tuple[int, ...] = input_bytes
        self.callstack: Tuple[str, ...] = callstack
        self.is_cavity = False

    @classmethod
    def cavity(self, input_bytes: CavityType):
        """A cavity has no callstack, since a cavity is a set of input bytes that was not operated on"""
        return self(input_bytes, callstack=())

    def __hash__(self):
        return hash((self.input_bytes, self.callstack, self.is_cavity))

    def __eq__(self, other):
        return (
            isinstance(other, CFLogEntry)
            and other.input_bytes == self.input_bytes
            and other.callstack == self.callstack
            and other.is_cavity == self.is_cavity
        )

    def __len__(self):
        return 2

    def __getitem__(self, item):
        if item == 0 or item == -2:
            return self.input_bytes
        elif item == 1 or item == -1:
            return self.callstack
        else:
            raise IndexError(item)

    # def __iter__(self):
    #     yield self.input_bytes
    #     yield self.callstack

    def __str__(self):
        return f"{', '.join(map(str, self.input_bytes))} -> {', '.join(self.callstack)}"


def context_string(
    input_file: Path,
    all_offsets: Iterable[int],
    offsets: Set[int],
    buffer_bytes: int = 5,
) -> Tuple[str, str]:
    with open(input_file, "rb") as f:
        context: List[str] = []
        highlights: List[str] = []
        escaped_strings = {
            b"'": "'",
            b'"': '"',
            b"\n": "n",
            b"\t": "t",
            b"\r": "r",
            b"\b": "b",
            b"\0": "0",
        }
        byte_sections: List[List[Tuple[int, bool]]] = []

        for offset in sorted(all_offsets):
            if byte_sections and byte_sections[-1][-1][0] >= offset - buffer_bytes - 1:
                # it is contiguous
                while byte_sections[-1][-1][0] < offset - 1:
                    byte_sections[-1].append((byte_sections[-1][-1][0] + 1, False))
                while byte_sections[-1][-1][0] >= offset:
                    byte_sections[-1].pop()
                byte_sections[-1].append((offset, True))
            else:
                new_section = []
                for byte_before in range(max(0, offset - buffer_bytes), offset):
                    new_section.append((byte_before, False))
                new_section.append((offset, True))
                byte_sections.append(new_section)
            if buffer_bytes > 0:
                byte_sections[-1].extend(
                    ((b, False) for b in range(offset + 1, offset + buffer_bytes + 1))
                )

        for i, section in enumerate(byte_sections):
            if i > 0:
                context.append("[magenta]…[/magenta]")
                highlights.append(" ")
            for offset, is_read in section:
                f.seek(offset)
                value_bytes = f.read(1)
                if value_bytes is None or len(value_bytes) == 0:
                    continue
                elif value_bytes[:1] in escaped_strings:
                    value = f"[orange]\\{escaped_strings[value_bytes[:1]]}[/orange]"
                    new_bytes = 2
                elif value_bytes[0] == ord(" "):
                    value = "␣"
                    new_bytes = 1
                elif 32 <= value_bytes[0] <= 126:
                    value = value_bytes[:1].decode("utf-8")
                    new_bytes = 1
                else:
                    value = f"[orange]0x{value_bytes[0]:02x}[/orange]"
                    new_bytes = 4
                if not is_read:
                    value = f"[dim]{value}[/dim]"
                context.append(value)
                if offset in offsets:
                    assert is_read
                    highlights.append(f"[red]{'↑' * new_bytes}[/red]")
                else:
                    highlights.append(" " * new_bytes)
        return "".join(context), "".join(highlights)


class CFLog(ListNode[CFLogEntry]):
    def __init__(self, entries: Iterable[CFLogEntry]):
        entries = tuple(entries)
        super().__init__(entries)
        self.entries: Tuple[CFLogEntry, ...] = entries

    def __hash__(self):
        return hash(self.entries)

    def __eq__(self, other):
        return isinstance(other, CFLog) and self.entries == other.entries

    def __getitem__(self, item):
        return self.entries[item]

    def __len__(self):
        return len(self.entries)

    def __iter__(self):
        yield from self.entries

    def __str__(self):
        return "\n".join(map(str, self.entries))


class CachedTDAGTraverser:
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


class Analysis:
    def get_cflog(self, tdag: TDFile, functions_list, with_cavities=False) -> CFLog:
        """A placeholder for now: returns the entire CFLog, though we will
        eventually want to experiment with different window types (sliding vs
        fixed, size of window, etc.)"""
        return CFLog(self._get_cflog_entries(tdag, functions_list, with_cavities))

    def _get_cavities(self, tdag: TDFile) -> List[CFLogEntry]:
        """Builds the Input/Output mapping for the tdag so that we can figure
        out which input offsets were never operated on (are cavities). Like
        with the CFLog computations, this can be expensive if the tdag is very
        large."""
        file_cavities = InputOutputMapping(tdag).file_cavities()
        cavs: List[CFLogEntry] = []
        for input_file_name in file_cavities:
            # there should be one valid input path since we traced one input
            for cavity in file_cavities[input_file_name]:
                cavs.append(CFLogEntry.cavity(cavity))
            break
        return cavs

    def _demangle_function_ids(self, functions_list) -> List[str]:
        demangled_functions_list: List[str] = []
        for function in functions_list:
            try:
                demangled_functions_list.append(cxxfilt.demangle(function))
            except cxxfilt.InvalidName:
                # if we can't demangle it, just keep the opaque name
                demangled_functions_list.append(function)
        return demangled_functions_list

    def _get_cflog_entries(
        self, tdag: TDFile, functions_list, with_cavities=False
    ) -> Iterable[CFLogEntry]:
        """Maps the function ID JSON to the TDAG control flow log."""
        cflog_tdag_section = tdag._get_section(taint_dag.TDControlFlowLogSection)
        cflog_tdag_section.function_id_mapping(
            self._demangle_function_ids(functions_list)
        )
        cflog_size = len(cflog_tdag_section)
        traverser = CachedTDAGTraverser(tdag, max_size=16384)

        # each cflog entry has a callstack and a label
        if not with_cavities:
            for event in tqdm(
                cflog_tdag_section,
                desc="tracing",
                leave=False,
                unit="CFLog Entries",
                total=cflog_size,
            ):
                if not isinstance(event, taint_dag.TDTaintedControlFlowEvent):
                    continue
                yield CFLogEntry(
                    (n.offset for n in traverser[event.label]),
                    event.callstack,
                )
            return
        else:
            cavities: List[CFLogEntry] = self._get_cavities(tdag)

            for event in tqdm(
                cflog_tdag_section,
                desc="tracing",
                leave=False,
                unit="CFLog entries interleaved with cavities",
                total=cflog_size,
            ):
                if not isinstance(event, taint_dag.TDTaintedControlFlowEvent):
                    continue

                input_bytes: List[int] = [n.offset for n in traverser[event.label]]

                # put the cavity in front of the first cflog entry containing a
                # greater than or equal input byte offset
                if cavities[0].input_bytes[-1] <= input_bytes[0]:
                    yield cavities[0]
                    cavities.pop(0)

                yield CFLogEntry(
                    input_bytes,
                    event.callstack,
                )

            # there may still be cavity entries left after there are no
            # more tainted control flow events!
            if len(cavities) > 0:
                for cavity in cavities:
                    yield cavity

            return

    def stringify_list(self, list) -> str:
        """Turns a list of byte offsets or a callstack into a printable string."""
        if list is None or len(list) == 0:
            return ""
        else:
            return ", ".join(map(str, list))

    def print_cols(
        self,
        offsets_A=None,
        callstack_A=None,
        callstack_B=None,
        offsets_B=None,
    ) -> None:
        # format:  bytesA   callstackA    callstackB  bytesB
        # -----------------------------------------------------
        # example: [2,3,4] | f(int foo) != f(int foo) | [5,6,7]
        # -----------------------------------------------------
        # example: [2,3,4] | f(int foo) !=
        # -----------------------------------------------------
        # example:         |            != f(int foo) | [5,6,7]
        # -----------------------------------------------------
        # example: [2,3,4] |             f()          | [2,3,4]

        fn: str = ""
        if not callstack_A and not callstack_B:
            fn = "UNKNOWN CALLSTACK"
        elif not callstack_B:
            fn = self.stringify_list(callstack_A)
        elif not callstack_A:
            fn = self.stringify_list(callstack_B)
        else:
            func_A = callstack_A[-1]
            func_B = callstack_B[-1]
            if func_A == func_B:
                return f"…, {func_A}"
            else:
                return f"…, {func_A} !!! != !!! …, {func_B}"

        horizontal_separator: str = "-" * (90)
        print(horizontal_separator)

        print(
            "| {:<15} | {:^100} | {:>15} |".format(
                self.stringify_list(offsets_A), fn, self.stringify_list(offsets_B)
            )
        )

    def show_cflog(
        self,
        tdag: TDFile,
        function_id_json,
        cavities=False,
    ) -> None:
        """Show the control-flow log mapped to relevant input bytes, for a single tdag."""
        cflog: CFLog = self.get_cflog(tdag, function_id_json, with_cavities=cavities)
        for entry in cflog:
            self.print_cols(offsets_A=entry[0], callstack_A=entry[1][-1])

    def get_lookahead_only_diff_entries(
        self,
        from_cflog_entries: Tuple[CFLogEntry, ...],
        to_cflog_entries: Tuple[CFLogEntry, ...],
    ) -> Iterable[Tuple[CFLogEntry, CFLogEntry]]:
        """This is a refactored version of the original ubet implementation, sans graphtage. This means it only compares traces in the forward direction, not the backward direction."""
        len_from: int = len(from_cflog_entries)
        len_to: int = len(to_cflog_entries)
        idx_from: int = 0
        idx_to: int = 0

        # offsetsA, callstackA, callstackB, offsetsB
        while idx_from < len_from or idx_to < len_to:
            # pad the end of the shorter cflog with Nones if needed
            from_entry = from_cflog_entries[idx_from] if idx_from < len_from else None
            to_entry = to_cflog_entries[idx_to] if idx_to < len_to else None

            if from_entry is None:
                idx_to += 1
                yield (None, to_entry)

            elif to_entry is None:
                idx_from += 1
                yield (from_entry, None)

            # same bytes were processed in the two runs by different functionality
            elif from_entry.input_bytes == to_entry.input_bytes:
                idx_from += 1
                idx_to += 1
                yield (from_entry, to_entry)
            else:
                # check if we should be stepping A or B cflogs
                # depending on shortest path
                stepsA = 0
                stepsB = 0

                while idx_from + stepsA < len_from:
                    if (
                        from_cflog_entries[idx_from + stepsA].input_bytes
                        == to_entry.input_bytes
                    ):
                        break
                    stepsA += 1

                while idx_to + stepsB < len_to:
                    if (
                        to_cflog_entries[idx_to + stepsB].input_bytes
                        == from_entry.input_bytes
                    ):
                        break
                    stepsB += 1

                if stepsA < stepsB and from_entry is not None:
                    idx_from += 1
                    yield (from_entry, None)
                elif to_entry is not None:
                    idx_to += 1
                    yield (None, to_entry)
        return

    def get_differential_entries(
        self, from_cflog: CFLog, to_cflog: CFLog, use_graphtage: bool = True
    ) -> Iterable[Tuple[CFLogEntry, CFLogEntry]]:
        """Creates a printable differential between two cflogs. Once we have annotated the control flow log for each
        tdag with the separately recorded demangled function names in callstack format, walk through them and see what
        does not match. This matches up control flow log entries from each tdag. Return the matched-up, printable diff
        structure."""
        if not use_graphtage:
            # todo(kaoudis): once no longer needed, remove lookahead only
            self.get_lookahead_only_diff_entries(from_cflog.entries, to_cflog.entries)
        else:
            diff = from_cflog.diff(to_cflog)
            if diff.edit is None:
                print("Both cflogs are identical!")
                return
            elif not isinstance(diff.edit, SequenceEdit):
                raise ValueError(f"Unexpected edit type: {diff.edit!r}")
            for edit in diff.edit.edits():
                assert isinstance(edit.from_node, CFLogEntry)
                if isinstance(edit, Match):
                    assert isinstance(edit.to_node, CFLogEntry)
                    yield (edit.from_node, edit.to_node)
                elif isinstance(edit, Replace):
                    yield (edit.from_node, None)
                    yield (None, edit.to_node)
                elif isinstance(edit, Insert):
                    yield (None, edit.from_node)
                elif isinstance(edit, Remove):
                    yield (edit.from_node, None)
                elif isinstance(edit, dataclasses.DataClassEdit):
                    assert isinstance(edit.from_node, CFLogEntry)
                    assert isinstance(edit.to_node, CFLogEntry)
                    yield (edit.from_node, edit.to_node)
                else:
                    raise NotImplementedError(repr(edit))
        return

    def find_divergence(
        self,
        from_tdag: TDFile,
        to_tdag: TDFile,
        from_functions_list,
        to_functions_list,
        input_file: Optional[Path] = None,
    ):
        from_cflog = self.get_cflog(from_tdag, from_functions_list)
        print("Loaded CFLOG A")
        to_cflog = self.get_cflog(to_tdag, to_functions_list)
        print("Loaded CFLOG B")

        bytes_operated_from: Set[int] = set()
        bytes_operated_to: Set[int] = set()
        trace: List[
            Tuple[
                Tuple[Frozenset[int], Tuple[str, ...], Tuple[str, ...], Frozenset[int]]
            ]
        ] = []

        for from_node, to_node in self.get_differential_entries(
            from_cflog, to_cflog, use_graphtage=True
        ):
            from_node.input_bytes = frozenset(from_node.input_bytes)
            to_node.input_bytes = frozenset(to_node.input_bytes)
            trace.append(
                (
                    from_node.input_bytes,
                    from_node.callstack,
                    to_node.callstack,
                    to_node.input_bytes,
                )
            )
            bytes_operated_from |= from_node.input_bytes
            bytes_operated_to |= to_node.input_bytes

        console = Console()

        def print_differential(
            trace_name: str,
            all_offsets: Iterable[int],
            offsets: Set[int],
            callstack: Iterable[str],
        ):
            console.print(
                f"[blue]Trace {trace_name}[/blue] operated on input offsets "
                f"{'[gray],[/gray] '.join(map(str, offsets))} that were never operated on by the other "
                f"trace at"
            )
            if input_file is not None:
                context, highlights = context_string(input_file, all_offsets, offsets)
                console.print(f"\tContext: {context}")
                console.print(f"\t         {highlights}")
            for c in callstack:
                console.print(f"\t[magenta]{c}[/magenta]")

        for from_bytes, from_callstack, to_callstack, to_bytes in trace:
            if from_bytes == to_bytes:
                continue
            if from_bytes - bytes_operated_to:
                print_differential(
                    "A", from_bytes, from_bytes - bytes_operated_to, from_callstack
                )
            if to_bytes - bytes_operated_from:
                print_differential(
                    "B", to_bytes, to_bytes - bytes_operated_from, to_callstack
                )

    def show_cflog_diff(
        self,
        tdagA: TDFile,
        tdagB: TDFile,
        functions_list_A,
        functions_list_B,
        cavities: bool = False,
    ) -> None:
        """Build and print the aligned differential."""
        cflogA: CFLog = self.get_cflog(tdagA, functions_list_A, with_cavities=cavities)
        cflogB: CFLog = self.get_cflog(tdagB, functions_list_B, with_cavities=cavities)

        table = Table(title="Trace Differentials", show_lines=True, width=132)
        table.add_column(
            Text("Trace A Input Bytes", style="blue"), justify="right", no_wrap=False
        )
        table.add_column(
            Text("Callstack", style="magenta"), justify="center", no_wrap=False
        )
        table.add_column(
            Text("Trace B Input Bytes", style="blue"), justify="left", no_wrap=False
        )

        for from_node, to_node in self.get_differential_entries(
            cflogA, cflogB, use_graphtage=True
        ):
            if not from_node.callstack and not to_node.callstack:
                callstack = Text("Unknown Callstack", style="italic red")
            elif not from_node.callstack:
                callstack = "[gray],[/gray] ".join(
                    f"[magenta]{c}[/magenta]" for c in to_node.callstack
                )
            elif not to_node.callstack:
                callstack = "[gray],[/gray] ".join(
                    f"[magenta]{c}[/magenta]" for c in from_node.callstack
                )
            else:
                from_func = from_node.callstack[-1]
                to_func = to_node.callstack[-1]
                if from_func == to_func:
                    callstack = f"[gray]…,[/gray] [magenta]{from_func}[/magenta]"
                else:
                    callstack = (
                        f"[gray]…,[/gray] [magenta]{from_func}[/magenta] [red]!=[/red] [gray]…,[/gray] "
                        f"[magenta]{to_func}[/magenta]"
                    )
            from_bytes_text = f"[gray],[/gray]".join(
                f"[blue]{b}[/blue]" for b in from_node.input_bytes
            )
            to_bytes_text = f"[gray],[/gray]".join(
                f"[blue]{b}[/blue]" for b in to_node.input_bytes
            )
            table.add_row(from_bytes_text, callstack, to_bytes_text)
        Console().print(table)

    def compare_run_trace(self, tdag_a: TDFile, tdag_b: TDFile, cavities=False):
        if cavities:
            mapping_a = InputOutputMapping(tdag_a).file_cavities()
            mapping_b = InputOutputMapping(tdag_b).file_cavities()
            symmetric_diff = set(mapping_a.items()).symmetric_difference(
                set(mapping_b.items())
            )
            print("...CAVITY SYMMETRIC DIFFERENCE...")
            for cavity in symmetric_diff:
                print(f"{cavity[0]}")
                for ct in cavity[1]:
                    print(f"\t{ct}")

        print("...EVENTS SYMMETRIC DIFFERENCE...")
        for eventA, idxA, eventB, idxB in zip(
            tdag_a.events(),
            range(0, len(tdag_a.events)),
            tdag_b.events(),
            range(0, len(tdag_b.events)),
        ):
            fnA = cxxfilt.demangle(tdag_a.fn_headers[eventA.fnidx][0])
            fnB = cxxfilt.demangle(tdag_b.fn_headers[eventB.fnidx][0])
            print(f"A: [{idxA}] {eventA} {fnA}, B: [{idxB}] {eventB} {fnB}")
