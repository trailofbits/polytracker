#!/usr/bin/python

from functools import partialmethod
import json
from .oi import OutputInputMapping
from pathlib import Path
from polytracker import taint_dag
from polytracker.mapping import InputOutputMapping
import subprocess
from sys import stdin
import datetime
from tqdm import tqdm

import cxxfilt

tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)
OUTPUT_COLUMN_WIDTH = 40


def run_binary(
    binary_path: Path, arguments: list[str], tstamp: float, instrumented=True
):
    """Runs the Polytracker-instrumented binary using the appropriate environment variables. Requires a Polytracker-capable environment, meaning should generally be run in the Polytracker container to avoid having to set up hacked custom LLVM, GLLVM, and friends."""

    if instrumented:
        # instead of producing polytracker.tdag as POLYDB, use the binary name
        e = {
            "POLYDB": f"{binary_path.name}-{tstamp}.tdag",
            "POLYTRACKER_STDOUT_SINK": "1",
            "POLYTRACKER_LOG_CONTROL_FLOW": "1",
        }
    else:
        e = {}

    args = [binary_path, "-i", *arguments, f"-o {binary_path.name}-{tstamp}.out.png"]
    print(args)
    ret = subprocess.run(args, env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    return ret


def runner(buildA: Path, buildB: Path, program_args: list[str] = None) -> None:
    """Reads a set of file names from stdin and feeds them to both --build_a and --build_b binaries.

    This is the primary driver for testing two binaries. It's possible to test two instrumented differing builds, or an uninstrumented and an instrumented build.
    """
    nameA: str = buildA.name
    nameB: str = buildB.name

    tstamp: str = datetime.datetime.today().strftime("%Y-%b-%d-%H-%M")

    targetdir = Path(f"./output-{tstamp}")
    targetdir = targetdir.absolute()
    if not targetdir.exists():
        targetdir.mkdir(0o755)
    log = targetdir / "log.txt"
    print(f"Sending (A {nameA} | B {nameB}) {program_args} run output to {log.name}...")

    print(f"{nameA} {program_args}...")
    runA = run_binary(buildA, program_args, tstamp)

    with open(targetdir / f"{nameA}-stdout-raw", "wb") as f:
        f.write(runA.stdout)
    with open(targetdir / f"{nameA}-stderr-raw", "wb") as f:
        f.write(runA.stderr)

    print(f"{nameB} {program_args}...")
    runB = run_binary(buildB, program_args, tstamp)

    with open(targetdir / f"{nameB}-stdout-raw", "wb") as f:
        f.write(runB.stdout)
    with open(targetdir / f"{nameB}-stderr-raw", "wb") as f:
        f.write(runB.stderr)

    # combined run information
    with open(log, "w") as f:
        f.write(f"'(A {nameA} | B {nameB}) {program_args}' run output\n--------\n")
        f.write(f"{nameA}-stdout(utf-8): {runA.stdout.decode('utf-8')}\n--------\n")
        f.write(f"{nameA}-stderr(utf-8): {runA.stderr.decode('utf-8')}\n--------\n")
        f.write(f"{nameB}-stdout(utf-8): {runB.stdout.decode('utf-8')}\n--------\n")
        f.write(f"{nameB}-stderr(utf-8): {runB.stderr.decode('utf-8')}\n--------\n")


def node_equals(n1, n2):
    """Polytracker TDAG node comparator."""
    if type(n1) is not type(n2):
        return False

    if n1.affects_control_flow != n2.affects_control_flow:
        return False

    if isinstance(n1, taint_dag.TDSourceNode):
        return n1.idx == n2.idx and n1.offset == n2.offset
    elif isinstance(n1, taint_dag.TDUnionTaint):
        return n1.left == n2.left and n1.right == n2.right
    elif isinstance(n1, taint_dag.TDRangeNode):
        return n1.first == n2.first and n1.last == n2.last

    assert isinstance(n1, taint_dag.TDUntaintedNode)
    return True


def input_set(first_label: int, tdag) -> Set[int]:
    q = [first_label]
    ret = set()
    seen = set()
    while q:
        label = q.pop()
        if label in seen:
            continue
        seen.add(label)

        n = tdag.decode_node(label)
        if isinstance(n, taint_dag.TDSourceNode):
            ret.add(n)
        elif isinstance(n, taint_dag.TDUnionNode):
            q.append(n.left)
            q.append(n.right)
        else:
            for lbl in range(n.first, n.last + 1):
                q.append(lbl)

    return ret


def input_offsets(tdag, first_taint_label: int = -1):
    """Figure out where the entry's taint label comes from in the input. To avoid the need to return multiple results, squash labels that descend from the same input offset(s) iff they are duplicates."""
    if first_taint_label != -1:
        return sorted(map(lambda n: n.offset, input_set(first_taint_label, tdag)))
    else:
        offsets = {}
        for input_label in tdag.input_labels():
            nodes = tdag.decode_node(input_label)
            offset = nodes.offset
            if offset in offsets:
                offsets[offset].append(nodes)
            else:
                offsets[offset] = [nodes]

        # Squash multiple labels at same offset if they are equal
        for offset, nodes in offsets.items():
            if all(node_equals(node, nodes[0]) for node in nodes):
                offsets[offset] = nodes[:1]
        return offsets


def get_cflog_entries(tdag: Path, function_id_path: Path) -> list[tuple]:
    """Maps the function ID JSON to the TDAG control flow log."""
    with open(function_id_path) as function_id_json:
        functions_list = json.load(function_id_json)
    cflog = tdag._get_section(taint_dag.TDControlFlowLogSection)

    demangled_functions_list = []
    for function in functions_list:
        try:
            demangled_functions_list.append(cxxfilt.demangle(function))
        except cxxfilt.InvalidName as e:
            print(
                f"Unable to demangle the function name '{function}' since cxx.InvalidName was raised, but attempting to continue..."
            )
            demangled_functions_list.append(function)
    cflog.function_id_mapping(demangled_functions_list)

    return list(
        map(
            lambda entry: (input_offsets(tdag, entry.label), entry.callstack),
            filter(
                lambda maybe_tainted_event: isinstance(
                    maybe_tainted_event, taint_dag.TDTaintedControlFlowEvent
                ),
                cflog,
            ),
        )
    )


def print_cols(dbg, release, additional=""):
    """Prettyprinter"""
    print(
        (dbg.ljust(OUTPUT_COLUMN_WIDTH))
        + release.ljust(OUTPUT_COLUMN_WIDTH)
        + additional
    )


def show_cflog(tdag: Path, function_id_path: Path, cavities=False):
    if cavities:
        file_cavities = InputOutputMapping(tdag).file_cavities()
        print("...FILE CAVITIES...")
        for c in file_cavities.items():
            print(f"{c[0]}")
            for cav_byte in c[1]:
                print(f"\t{cav_byte}")

    print("...CONTROL FLOW LOG...")
    cflog = get_cflog_entries(tdag, function_id_path)

    for entry in range(0, len(cflog)):
        print_cols(str(entry), "", "")


def compare_cflog(
    tdagA: Path, tdagB: Path, function_id_pathA: Path, function_id_pathB: Path
):
    """Once we have annotated the control flow log for each tdag with the separately recorded demangled function names, walk through them and see what does not match. This matches up control flow log entries from each tdag."""
    cflogA = get_cflog_entries(tdagA, function_id_pathA)
    cflogB = get_cflog_entries(tdagB, function_id_pathB)

    print("COMPARE CONTROL FLOW LOGS")
    n = max(len(cflogA), len(cflogB))

    lenA = len(cflogA)
    lenB = len(cflogB)

    idxA = 0
    idxB = 0
    while idxA < lenA or idxB < lenB:
        entryA = cflogA[idxA] if idxA < lenA else None
        entryB = cflogB[idxB] if idxB < lenB else None

        if entryA is None:
            print_cols("", str(entryB), "")
            idxB += 1
            continue

        if entryB is None:
            print_cols(str(entryA), "", "")
            idxA += 1
            continue

        callstackA = str(entryA[1])
        callstackB = str(entryB[1])

        if entryA[0] == entryB[0]:
            print_cols(
                str(entryA[0]),
                str(entryB[0]),
                f" !!! A: {callstackA} != B: {callstackB}"
                if callstackA != callstackB
                else "",
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
                print_cols(str(entryA[0]), "", callstackA)
                idxA += 1
            else:
                print_cols("", str(entryB[0]), callstackB)
                idxB += 1

    return


def compare_run_trace(tdag_a, tdag_b, cavities=False):
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


def enum_diff(dbg_tdfile, rel_tdfile):
    offset_dbg = input_offsets(dbg_tdfile)
    offset_rel = input_offsets(rel_tdfile)

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
                if not node_equals(offset_dbg[i][0], offset_rel[i][0]):
                    print(f"DBG {offset_dbg[i][0]} - REL {offset_rel[i][0]}")
            elif offset_dbg[i] != offset_rel[i]:
                print(f"ED (count): DBG {offset_dbg[i]} - REL {offset_rel[i]}")

        i += 1


def compare_inputs_used(dbg_tdfile, rel_tdfile):
    dbg_mapping = OutputInputMapping(dbg_tdfile).mapping()
    rel_mapping = OutputInputMapping(rel_tdfile).mapping()
    inputs_dbg = set(x[1] for x in dbg_mapping)
    inputs_rel = set(x[1] for x in rel_mapping)
    print(f"Input diffs: {sorted(inputs_rel-inputs_dbg)}")
