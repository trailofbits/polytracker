#!/usr/bin/python

from argparse import ArgumentParser
from functools import partialmethod
import json
from oi import OutputInputMapping
from os import rename
from pathlib import Path
from polytracker import PolyTrackerTrace, taint_dag
from polytracker.mapping import InputOutputMapping
import subprocess
from sys import stdin
import datetime
from tqdm import tqdm

import cxxfilt

tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)
OUTPUT_COLUMN_WIDTH = 40

parser = ArgumentParser(
    prog="compare_tdags",
    description="Compares TDAGs",
)
parser.add_argument(
    "-a",
    "--build_a",
    type=Path,
    help="Path to the first binary build to compare (should be the same software as build b, just built with different options)",
)
parser.add_argument(
    "-ta",
    "--tdag_a",
    type=Path,
    help="Path to the first TDAG (A) trace to compare",
)
parser.add_argument(
    "-fa",
    "--function_id_json_a",
    type=Path,
    help="Path to functionid.json function trace for TDAG A (created by polytracker's cflog pass)",
)
parser.add_argument(
    "-b",
    "--build_b",
    type=Path,
    help="Path to the second binary build to compare (should be the same software as build a, just built with different options)",
)
parser.add_argument(
    "-tb",
    "--tdag_b",
    type=Path,
    help="Path to the second TDAG (B) trace to compare (created by polytracker's cflog pass)",
)
parser.add_argument(
    "-fb",
    "--function_id_json_b",
    type=Path,
    help="Path to functionid.json function trace for TDAG B",
)
parser.add_argument(
    "-e",
    "--execute",
    type=str,
    nargs="+",
    help="command line arguments (including input) to run for each candidate build, for example `<executable_passed_with -a or -b> -i image.j2k -o image.pgm` would require `-i image.j2k -o image.pgm`",
)
parser.add_argument(
    "--cflog",
    action="store_true",
    help="Compare Control Flow Logs (requires -a and -b)",
)
parser.add_argument(
    "--inout",
    action="store_true",
    help="Compare Input-Output mapping (requires -a and -b)",
)
parser.add_argument(
    "--outin",
    action="store_true",
    help="Compare Output-Input mapping (requires -a and -b)",
)
parser.add_argument(
    "--runtrace", action="store_true", help="Compare runtrace (requires -a and -b)"
)
parser.add_argument(
    "--inputsused",
    action="store_true",
    help="Compare inputs used (requires -a and -b)",
)
parser.add_argument(
    "--enumdiff",
    action="store_true",
    help="Enumerate differences (kind of) (requires -a and -b)",
)
args = parser.parse_args()


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


def input_offsets(tdag):
    """Figure out where each node comes from in the input, and squash labels that descend from the same input offset(s) iff they are duplicates."""
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
    cflog.function_id_mapping(list(map(cxxfilt.demangle, functions_list)))
    return list(
        map(
            lambda entry: (input_offsets(entry.label, tdag), entry.callstack),
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


def compare_cflog(
    tdagA: Path, tdagB: Path, function_id_pathA: Path, function_id_pathB: Path
):
    """Once we have annotated the control flow log for each tdag with the separately recorded demangled function names, walk through them and see what does not match."""
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


def compare_run_trace(tdag_a, tdag_b):
    for eventA, idxA, eventB, idxB in zip(
        tdag_a.events,
        range(0, len(tdag_a.events)),
        tdag_b.events,
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


if __name__ == "__main__":
    if args.execute:
        print(f"Running '{args.execute}' for {args.build_a} and {args.build_b}")
        runner(args.build_a, args.build_b, args.execute)
    elif args.tdag_a and args.tdag_b:
        print(f"Comparing {args.tdag_a} and {args.tdag_b}")
        traceA = PolyTrackerTrace.load(args.tdag_a)
        traceB = PolyTrackerTrace.load(args.tdag_b)

        if args.cflog:
            print("Control flow log comparison...")
            compare_cflog(
                tdagA=traceA.tdfile,
                tdagB=traceB.tdfile,
                function_id_pathA=args.function_id_json_a,
                function_id_pathB=args.function_id_json_b,
            )

        if args.runtrace:
            print("Run trace comparison...")
            compare_run_trace(traceA.tdfile, traceB.tdfile)

        if args.inputsused:
            print("Inputs comparison...")
            compare_inputs_used(traceA.tdfile, traceB.tdfile)

        if args.enumdiff:
            print("Enum diff...")
            enum_diff(traceA.tdfile, traceB.tdfile)
    else:
        print("Error: Need to provide either -a and -b, or --locate")
        parser.print_help()
