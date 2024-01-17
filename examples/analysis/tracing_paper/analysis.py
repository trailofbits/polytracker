#!/usr/bin/python

from functools import partialmethod
from oi import OutputInputMapping
from pathlib import Path
from polytracker import taint_dag, TDFile
from polytracker.mapping import CavityType, InputOutputMapping
from sys import stdin
from tqdm import tqdm
from typing import Any, Dict, List, Set, Tuple
import cxxfilt

tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)


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

    def get_cflog_entries(
        self, tdag: TDFile, functions_list, verbose=False
    ) -> List[Tuple[List[int], List[str]]]:
        """Maps the function ID JSON to the TDAG control flow log."""
        cflog = tdag._get_section(taint_dag.TDControlFlowLogSection)

        demangled_functions_list = []
        for function in functions_list:
            try:
                demangled_functions_list.append(cxxfilt.demangle(function))
            except cxxfilt.InvalidName:
                if verbose:
                    print(
                        f"Unable to demangle '{function}' since cxx.InvalidName was raised; attempting to continue without demangling that function name anyway..."
                    )
                demangled_functions_list.append(function)

        cflog.function_id_mapping(demangled_functions_list)

        # each cflog entry has a callstack and a label
        return list(
            map(
                lambda event: (
                    self.sorted_ancestor_offsets(event.label, tdag),
                    event.callstack,
                ),
                filter(
                    # cflog also contains function entries and exits
                    lambda cflog_event: isinstance(
                        cflog_event, taint_dag.TDTaintedControlFlowEvent
                    ),
                    cflog,
                ),
            )
        )

    def stringify_list(self, list) -> str:
        """Turns a list of byte offsets or a callstack into a printable string."""
        if list is None or len(list) == 0:
            return ""
        else:
            return str(list)

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
        if callstack_A != callstack_B:
            fn = "{:<40} !!! != !!! {:>40}".format(
                self.stringify_list(callstack_A), self.stringify_list(callstack_B)
            )
        else:
            fn = self.stringify_list(callstack_A)

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
        cflog: list[tuple] = self.get_cflog_entries(tdag, function_id_json, verbose)

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
        cflogA,
        cflogB,
        verbose=False,
    ) -> List[Tuple[str, str, str, str]]:
        """Creates a printable differential between two cflogs. Once we have annotated the control flow log for each tdag with the separately recorded demangled function names in callstack format, walk through them and see what does not match. This matches up control flow log entries from each tdag. Return the matched-up, printable diff structure."""
        lenA: int = len(cflogA)
        lenB: int = len(cflogB)
        idxA: int = 0
        idxB: int = 0

        # offsetsA, callstackA, callstackB, offsetsB
        trace_diff: List[Tuple[str, str, str, str]] = []

        while idxA < lenA or idxB < lenB:
            entryA = cflogA[idxA] if idxA < lenA else None
            entryB = cflogB[idxB] if idxB < lenB else None

            if not verbose:
                # gets only last entry of callstack in non-verbose mode - it's often enough detail.
                if entryA is not None and len(entryA[1]) > 0:
                    callA = entryA[1][-1]
                else:
                    callA = None

                if entryB is not None and len(entryB[1]) > 0:
                    callB = entryB[1][-1]
                else:
                    callB = None

            else:
                callA = entryA[1]
                callB = entryB[1]

            if entryA is None:
                trace_diff.append(
                    (
                        None,
                        None,
                        callB,
                        entryB[0],
                    )
                )
                idxB += 1
                continue

            if entryB is None:
                trace_diff.append(
                    (
                        entryA[0],
                        callA,
                        None,
                        None,
                    )
                )
                idxA += 1
                continue

            # same bytes were processed in the two runs by different functionality
            if entryA[0] == entryB[0]:
                trace_diff.append(
                    (
                        entryA[0],
                        callA,
                        callB,
                        entryB[0],
                    )
                )
                idxA += 1
                idxB += 1
            else:
                # check if we should be stepping A or B cflogs
                # depending on shortest path
                stepsA = 0
                stepsB = 0

                while idxA + stepsA < lenA:
                    if cflogA[idxA + stepsA][0] == entryB[0]:
                        break
                    stepsA += 1

                while idxB + stepsB < lenB:
                    if cflogB[idxB + stepsB][0] == entryA[0]:
                        break
                    stepsB += 1

                if stepsA < stepsB:
                    # bytesA, callA, callB, bytesB
                    trace_diff.append(
                        (
                            entryA[0],
                            callA,
                            None,
                            None,
                        )
                    )
                    idxA += 1
                else:
                    # bytesA, callA, callB, bytesB
                    trace_diff.append(
                        (
                            None,
                            None,
                            callB,
                            entryB[0],
                        )
                    )
                    idxB += 1

        return trace_diff

    def show_cflog_diff(
        self,
        tdagA: TDFile,
        tdagB: TDFile,
        functions_list_A,
        functions_list_B,
        cavities: bool = False,
        verbose: bool = False,
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

        diff: List[Tuple[str, str, str, str]] = self.get_differential_entries(
            cflogA, cflogB, verbose
        )

        for entry in diff:
            self.print_cols(
                offsets_A=entry[0],
                callstack_A=entry[1],
                callstack_B=entry[2],
                offsets_B=entry[3],
            )

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

    def enum_diff(self, dbg_tdfile: TDFile, rel_tdfile: TDFile):
        offset_dbg = self.input_offsets(dbg_tdfile)
        offset_rel = self.input_offsets(rel_tdfile)

        i = 0
        maxl = max(offset_dbg, key=int)
        maxr = max(offset_rel, key=int)
        maxtot = max(maxl, maxr)
        while i <= maxtot:
            if i in offset_dbg and i not in offset_rel:
                print(f"Only DBG: {offset_dbg[i]}")
            elif i in offset_rel and i not in offset_dbg:
                print(f"Only REL: {offset_rel[i]}")
            elif i in offset_dbg and i in offset_rel:
                if len(offset_dbg[i]) == 1 and len(offset_rel[i]) == 1:
                    if not self.node_equals(offset_dbg[i][0], offset_rel[i][0]):
                        print(f"DBG {offset_dbg[i][0]} - REL {offset_rel[i][0]}")
                elif offset_dbg[i] != offset_rel[i]:
                    print(f"ED (count): DBG {offset_dbg[i]} - REL {offset_rel[i]}")

            i += 1

    def compare_inputs_used(self, dbg_tdfile: TDFile, rel_tdfile: TDFile):
        dbg_mapping = OutputInputMapping(dbg_tdfile).mapping()
        rel_mapping = OutputInputMapping(rel_tdfile).mapping()
        inputs_dbg = set(x[1] for x in dbg_mapping)
        inputs_rel = set(x[1] for x in rel_mapping)
        print(f"Input diffs: {sorted(inputs_rel-inputs_dbg)}")
