#!/usr/bin/python

from functools import partialmethod
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

import cxxfilt
from graphtage import (
    dataclasses, GraphtageFormatter, Insert, IntegerNode, LeafNode, ListNode, Match, Remove, Replace, StringNode
)
import graphtage.printer as printer_module
from graphtage.sequences import SequenceEdit
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
    input_bytes_node: ListNode
    callstack_node: ListNode

    def __init__(self, input_bytes: Iterable[int], callstack: Iterable[str]):
        input_bytes = tuple(input_bytes)
        callstack = tuple(callstack)
        super().__init__(
            input_bytes_node=ListNode((IntegerNode(i) for i in input_bytes)),
            callstack_node=ListNode((CallStackEntry(c) for c in callstack))
        )
        self.input_bytes: Tuple[int, ...] = input_bytes
        self.callstack: Tuple[str, ...] = callstack

    def __hash__(self):
        return hash((self.input_bytes, self.callstack))

    def __eq__(self, other):
        return (
            isinstance(other, CFLogEntry)
            and other.input_bytes == self.input_bytes
            and other.callstack == self.callstack
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
        input_file: Path, all_offsets: Iterable[int], offsets: Set[int], buffer_bytes: int = 5
) -> Tuple[str, str]:
    with open(input_file, "rb") as f:
        context: List[str] = []
        highlights: List[str] = []
        escaped_strings = {
            b"'": "'",
            b'"': '"',
            b'\n': 'n',
            b'\t': 't',
            b'\r': 'r',
            b'\b': 'b',
            b'\0': '0'
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
                byte_sections[-1].extend(((b, False) for b in range(offset + 1, offset+buffer_bytes + 1)))

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
                elif value_bytes[0] == ord(' '):
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
                    highlights.append(' ' * new_bytes)
        return ''.join(context), ''.join(highlights)


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


class Analysis:
    def node_equals(self, n1: taint_dag.TDNode, n2: taint_dag.TDNode) -> bool:
        """Polytracker TDAG node comparator."""
        if type(n1) is not type(n2):
            return False

        if n1.affects_control_flow != n2.affects_control_flow:
            return False

        if isinstance(n1, taint_dag.TDSourceNode):
            return n1.idx == n2.idx and n1.offset == n2.offset
        elif isinstance(n1, taint_dag.TDUnionNode):
            return n1.left == n2.left and n1.right == n2.right
        elif isinstance(n1, taint_dag.TDRangeNode):
            return n1.first == n2.first and n1.last == n2.last

        assert isinstance(n1, taint_dag.TDUntaintedNode)
        return True

    def input_offsets(self, tdag: TDFile) -> Dict[int, List[taint_dag.TDNode]]:
        """Return the full organized set of tdag labels by input byte offset. Squashes labels that descend from the same input offset(s) iff they are duplicates."""
        offsets: Dict[int, List[taint_dag.TDNode]] = {}
        for input_label in tdag.input_labels():
            tdnode: taint_dag.TDNode = tdag.decode_node(input_label)
            offset: int = tdnode.offset

            if offset in offsets:
                offsets[offset].append(tdnode)
            else:
                offsets[offset] = [tdnode]

        # Squash multiple labels at same offset if they are equal
        for offset, tdnode in offsets.items():
            if all(self.node_equals(node, tdnode[0]) for node in tdnode):
                offsets[offset] = tdnode[:1]
        return offsets

    def ancestor_input_set(
        self, first_label: int, tdag: TDFile
    ) -> Set[taint_dag.TDNode]:
        """Returns the subset of source nodes that directly taint `first_label` by way of traversing the taint forest from the starting point of `first_label`."""
        q: List[int] = [first_label]
        input_set: Set[taint_dag.TDNode] = set()
        seen_labels: Set[int] = set()
        while q:
            label = q.pop()
            if label in seen_labels:
                continue
            seen_labels.add(label)

            node: taint_dag.TDNode = tdag.decode_node(label)
            if isinstance(node, taint_dag.TDSourceNode):
                input_set.add(node)
            elif isinstance(node, taint_dag.TDUnionNode):
                q.append(node.left)
                q.append(node.right)
            elif isinstance(node, taint_dag.TDRangeNode):
                for range_label_number in range(node.first, node.last + 1):
                    q.append(range_label_number)

        return input_set

    def sorted_ancestor_offsets(self, label: int, tdag: TDFile) -> List[int]:
        """Returns the subset of source offsets (integer input byte labels), in sorted order, that directly taint `label` by way of traversing the taint forest from the starting point of `label`."""
        return sorted(
            map(
                lambda node: node.offset,
                self.ancestor_input_set(label, tdag),
            )
        )

    def get_cflog_entries(self, tdag: TDFile, functions_list, verbose=False) -> CFLog:
        """Maps the function ID JSON to the TDAG control flow log."""
        cflog = tdag._get_section(taint_dag.TDControlFlowLogSection)

        demangled_functions_list = []
        for function in functions_list:
            try:
                demangled_functions_list.append(cxxfilt.demangle(function))
            except cxxfilt.InvalidName:
                if verbose:
                    print(
                        f"Unable to demangle '{function}' since cxx.InvalidName was raised; attempting to continue "
                        f"without demangling that function name anyway..."
                    )
                demangled_functions_list.append(function)

        cflog.function_id_mapping(demangled_functions_list)

        # each cflog entry has a callstack and a label
        return CFLog(
            (
                CFLogEntry(
                    self.sorted_ancestor_offsets(event.label, tdag),
                    event.callstack,
                )
                for event in cflog
                if isinstance(event, taint_dag.TDTaintedControlFlowEvent)
            )
        )

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

    def interleave_file_cavities(
        self,
        tdag: TDFile,
        cflog: list[tuple],
        verbose=False,
    ) -> List[Tuple[List[str], List[str]]]:
        """Put each cavity before the most relevant cflog entry. If any cavities remain, put them on the end of the interleaved list."""
        cavity_byte_sets: List[CavityType]
        file_cavities = InputOutputMapping(tdag).file_cavities()
        for input_file_name in file_cavities:
            if verbose:
                print(
                    f"Unused byte sections were observed from within instrumented program run on input '{input_file_name}';\n they will be interleaved in the below control flow log output..."
                )
            cavity_byte_sets = file_cavities[input_file_name]
            break

        ret: list[tuple] = []
        for prev, entry in zip([None] + cflog[:-1], cflog):
            # put each cavity before the most relevant cflog entry
            byte_set: CavityType
            for byte_set in cavity_byte_sets:
                if prev is not None and (
                    prev[0][-1] <= int(byte_set[0])
                    and prev[0][-1] <= int(byte_set[-1])
                    and entry[0][0] >= int(byte_set[-1])
                ):
                    ret.append(
                        (
                            f"CAVITY [{byte_set[0]}, {byte_set[1]})",
                            ["!!UNUSED RANGE (blind spot)!!"],
                        )
                    )
                    cavity_byte_sets.remove(byte_set)
            ret.append(entry)

        for remainder_set in cavity_byte_sets:
            ret.append(
                (
                    f"CAVITY [{remainder_set[0]}, {remainder_set[1]})",
                    ["!!UNUSED RANGE (blind spot)!!"],
                )
            )

        return ret

    def show_cflog(
        self, tdag: TDFile, function_id_json, cavities=False, verbose=False
    ) -> None:
        """Show the control-flow log mapped to relevant input bytes, for a single tdag."""
        cflog: CFLog = self.get_cflog_entries(tdag, function_id_json, verbose)

        if cavities:
            interleaved = self.interleave_file_cavities(tdag, cflog, verbose)
            for entry in interleaved:
                # entry structure = tuple(label, list(callstackEntry, ...))
                # show only the last function entry in the callstack
                self.print_cols(offsets_A=entry[0], callstack_A=entry[1][-1])
        else:
            for entry in cflog:
                self.print_cols(offsets_A=entry[0], callstack_A=entry[1][-1])

    def get_differential_entries(
        self,
        from_cflog: CFLog,
        to_cflog: CFLog,
        use_graphtage: bool = True,
        verbose: bool = False,
    ) -> Iterable[Tuple[Tuple[int, ...], Tuple[str, ...], Tuple[str, ...], Tuple[int, ...]]]:
        """Creates a printable differential between two cflogs. Once we have annotated the control flow log for each
        tdag with the separately recorded demangled function names in callstack format, walk through them and see what
        does not match. This matches up control flow log entries from each tdag. Return the matched-up, printable diff
        structure."""
        if use_graphtage:
            diff = from_cflog.diff(to_cflog)
            if diff.edit is None:
                print("Both cflogs are identical!")
                return
            elif not isinstance(diff.edit, SequenceEdit):
                raise ValueError(f"Unexpected edit type: {diff.edit!r}")
            for edit in diff.edit.edits():
                assert isinstance(edit.from_node, CFLogEntry)
                to_yield: List[Tuple[Optional[CFLogEntry], Optional[CFLogEntry]]] = []
                if isinstance(edit, Match):
                    assert isinstance(edit.to_node, CFLogEntry)
                    to_yield.append((edit.from_node, edit.to_node))
                elif isinstance(edit, Replace):
                    to_yield.append((edit.from_node, None))
                    to_yield.append((None, edit.to_node))
                elif isinstance(edit, Insert):
                    to_yield.append((None, edit.from_node))
                elif isinstance(edit, Remove):
                    to_yield.append((edit.from_node, None))
                elif isinstance(edit, dataclasses.DataClassEdit):
                    assert isinstance(edit.from_node, CFLogEntry)
                    assert isinstance(edit.to_node, CFLogEntry)
                    to_yield.append((edit.from_node, edit.to_node))
                else:
                    raise NotImplementedError(repr(edit))
                for from_node, to_node in to_yield:
                    assert from_node is not None or to_node is not None
                    if from_node is None:
                        yield (), (), to_node.callstack, to_node.input_bytes
                    elif to_node is None:
                        yield from_node.input_bytes, from_node.callstack, (), ()
                    else:
                        yield from_node.input_bytes, from_node.callstack, to_node.callstack, to_node.input_bytes
            return

        len_from: int = len(from_cflog)
        len_to: int = len(to_cflog)
        idx_from: int = 0
        idx_to: int = 0

        # offsetsA, callstackA, callstackB, offsetsB
        trace_diff: List[Tuple[str, str, str, str]] = []

        while idx_from < len_from or idx_to < len_to:
            entryA = from_cflog[idx_from] if idx_from < len_from else None
            entryB = to_cflog[idx_to] if idx_to < len_to else None

            if not verbose:
                # show only last entry of callstack in non-verbose mode - it's often enough detail.
                if entryA is not None and len(entryA[1]) > 0:
                    callstackA = entryA[1][-1]
                else:
                    callstackA = None

                if entryB is not None and len(entryB[1]) > 0:
                    callstackB = entryB[1][-1]
                else:
                    callstackB = None

            else:
                callstackA = entryA[1]
                callstackB = entryB[1]

            if entryA is None:
                trace_diff.append(
                    (
                        None,
                        None,
                        callstackB,
                        entryB[0],
                    )
                )
                idx_to += 1
                continue

            if entryB is None:
                trace_diff.append(
                    (
                        entryA[0],
                        callstackA,
                        None,
                        None,
                    )
                )
                idx_from += 1
                continue

            # same bytes were processed in the two runs by different functionality
            if entryA[0] == entryB[0]:
                trace_diff.append(
                    (
                        entryA[0],
                        callstackA,
                        callstackB,
                        entryB[0],
                    )
                )
                idx_from += 1
                idx_to += 1
            else:
                # check if we should be stepping A or B cflogs
                # depending on shortest path
                stepsA = 0
                stepsB = 0

                while idx_from + stepsA < len_from:
                    if from_cflog[idx_from + stepsA][0] == entryB[0]:
                        break
                    stepsA += 1

                while idx_to + stepsB < len_to:
                    if to_cflog[idx_to + stepsB][0] == entryA[0]:
                        break
                    stepsB += 1

                if stepsA < stepsB:
                    # bytesA, callA, callB, bytesB
                    trace_diff.append(
                        (
                            entryA[0],
                            callstackA,
                            None,
                            None,
                        )
                    )
                    idx_from += 1
                else:
                    # bytesA, callA, callB, bytesB
                    trace_diff.append(
                        (
                            None,
                            None,
                            callstackB,
                            entryB[0],
                        )
                    )
                    idx_to += 1

        return trace_diff

    def find_divergence(
            self, from_tdag: TDFile, to_tdag: TDFile, from_functions_list, to_functions_list, verbose: bool = False,
            input_file: Optional[Path] = None
    ):
        # TODO: Stop considering divergences after one trace crashes/ends
        # TODO: Also show other bytes read that were also read by the other trace

        from_cflog = self.get_cflog_entries(from_tdag, from_functions_list)
        to_cflog = self.get_cflog_entries(to_tdag, to_functions_list)

        bytes_operated_from: Set[int] = set()
        bytes_operated_to: Set[int] = set()
        trace: List[Tuple[Tuple[FrozenSet[int], Tuple[str, ...], Tuple[str, ...], FrozenSet[int]]]] = []

        for from_bytes, from_callstack, to_callstack, to_bytes in self.get_differential_entries(
                from_cflog, to_cflog, use_graphtage=True, verbose=verbose
        ):
            from_bytes = frozenset(from_bytes)
            to_bytes = frozenset(to_bytes)
            trace.append((from_bytes, from_callstack, to_callstack, to_bytes))
            bytes_operated_from |= from_bytes
            bytes_operated_to |= to_bytes

        console = Console()

        def print_differential(trace_name: str, all_offsets: Iterable[int], offsets: Set[int],
                               callstack: Iterable[str]):
            console.print(f"[blue]Trace {trace_name}[/blue] operated on input offsets "
                          f"{'[gray],[/gray] '.join(map(str, offsets))} that were never operated on by the other "
                          f"trace at")
            if input_file is not None:
                context, highlights = context_string(input_file, all_offsets, offsets)
                console.print(f"\tContext: {context}")
                console.print(f"\t         {highlights}")
            for c in reversed(list(callstack)):
                console.print(f"\t[magenta]{c}[/magenta]")

        for from_bytes, from_callstack, to_callstack, to_bytes in trace:
            if from_bytes == to_bytes:
                continue
            if from_bytes - bytes_operated_to:
                print_differential("A", from_bytes, from_bytes - bytes_operated_to, from_callstack)
            if to_bytes - bytes_operated_from:
                print_differential("B", to_bytes, to_bytes - bytes_operated_from, to_callstack)

    def show_cflog_diff(
        self,
        tdagA: TDFile,
        tdagB: TDFile,
        functions_list_A,
        functions_list_B,
        cavities: bool = False,
        verbose: bool = False
    ) -> None:
        """Build and print the aligned differential."""
        cflogA = self.get_cflog_entries(tdagA, functions_list_A)
        if cavities:
            interleavedA = self.interleave_file_cavities(tdagA, cflogA)
            if verbose:
                print("Using interleaved cavities and TDAG A...")
            cflogA = interleavedA

        cflogB = self.get_cflog_entries(tdagB, functions_list_B)
        if cavities:
            interleavedB = self.interleave_file_cavities(tdagB, cflogB)
            if verbose:
                print("Using interleaved cavities and TDAG B...")
            cflogB = interleavedB

        table = Table(title="Trace Differentials", show_lines=True, width=132)
        table.add_column(Text("Trace A Input Bytes", style="blue"), justify="right", no_wrap=False)
        table.add_column(Text("Callstack", style="magenta"), justify="center", no_wrap=False)
        table.add_column(Text("Trace B Input Bytes", style="blue"), justify="left", no_wrap=False)

        for from_bytes, from_callstack, to_callstack, to_bytes in self.get_differential_entries(
            cflogA, cflogB, use_graphtage=True, verbose=verbose
        ):
            if not from_callstack and not to_callstack:
                callstack = Text("Unknown Callstack", style="italic red")
            elif not from_callstack:
                callstack = "[gray],[/gray] ".join(f"[magenta]{c}[/magenta]" for c in to_callstack)
            elif not to_callstack:
                callstack = "[gray],[/gray] ".join(f"[magenta]{c}[/magenta]" for c in from_callstack)
            else:
                from_func = from_callstack[-1]
                to_func = to_callstack[-1]
                if from_func == to_func:
                    callstack = f"[gray]…,[/gray] [magenta]{from_func}[/magenta]"
                else:
                    callstack = (f"[gray]…,[/gray] [magenta]{from_func}[/magenta] [red]!=[/red] [gray]…,[/gray] "
                                 f"[magenta]{to_func}[/magenta]")
            from_bytes_text = f"[gray],[/gray]".join(f"[blue]{b}[/blue]" for b in from_bytes)
            to_bytes_text = f"[gray],[/gray]".join(f"[blue]{b}[/blue]" for b in to_bytes)
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
