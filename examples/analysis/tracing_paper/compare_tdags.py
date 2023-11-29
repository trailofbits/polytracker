#!/usr/bin/python

from argparse import ArgumentParser
from functools import partialmethod
from json import load
from oi import OutputInputMapping
from os import rename
from pathlib import Path
from polytracker import PolyTrackerTrace, taint_dag
from polytracker.mapping import InputOutputMapping
import subprocess
from sys import stdin
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
    help="Path to functionid.json function trace for TDAG A",
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
    help="Path to the second TDAG (B) trace to compare",
)
parser.add_argument(
    "-fb",
    "--function_id_json_b",
    type=Path,
    help="Path to functionid.json function trace for TDAG B",
)
parser.add_argument(
    "-l",
    "--locate",
    action="store_true",
    help="Filenames read from stdin are run in the instrumented binary and any discrepancies between builds are stored in the output directory. Can be executed as 'find dir -type f | python3 compare_tdags.py -l'",
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


def run_binary(binary_path: Path, input: Path, output_dir: Path, instrumented=True):
    """Runs the Polytracker-instrumented binary using the appropriate environment variables. Requires a Polytracker-capable environment, meaning should generally be run in the Polytracker container to avoid having to set up hacked custom LLVM, GLLVM, and friends."""

    if instrumented:
        db_name: Path = binary_path.parts[-1]
        e = {
            "POLYDB": str(db_name),
            "POLYTRACKER_STDOUT_SINK": "1",
            "POLYTRACKER_LOG_CONTROL_FLOW": "1",
        }
    else:
        e = {}

    args = [binary_path, input]
    ret = subprocess.run(args, env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if db_name.exists():
        rename(db_name, output_dir / db_name)
    elif instrumented:
        raise RuntimeError(
            "Ran a Polytracker-instrumented binary, and could not find the DB after? Check manually if it exists."
        )

    return ret


def locate_candidates(buildA: Path, buildB: Path) -> None:
    """Reads a set of file names from stdin and feeds them to both --build_a and --build_b binaries.

    This is the primary driver for testing two binaries. It's possible to test two instrumented differing builds, or an uninstrumented and an instrumented build.

    Having collected files your instrumented parser can process in a directory, you can feed them to this script's stdin using something along the lines of `find <directory_name/> -type f | python3 eval_nitro.py --locate`.

    A "candidate input" is a file for which output differs between the two builds.
    """
    for filename in stdin:
        input_file = Path(filename.rstrip()).absolute()
        if not input_file.exists():
            print(f"Skipping non-existing {input_file}.")
            continue

        nameA: str = buildA.name
        nameB: str = buildB.name

        targetdir = Path("./output") / input_file.name
        targetdir = targetdir.absolute()
        if not targetdir.exists():
            targetdir.mkdir(0o755)
        log = targetdir / "log.txt"
        print(
            f"Sending {input_file.name} A {nameA} | B {nameB} run output to {log.name}..."
        )

        print(f"{nameA} processing {input_file}...")
        runA = run_binary(binary_path=buildA, input=input_file, output_dir=targetdir)

        with open(targetdir / f"{nameA}-stdout-raw", "wb") as f:
            f.write(runA.stdout)
        with open(targetdir / f"{nameA}-stderr-raw", "wb") as f:
            f.write(runA.stderr)

        print(f"{nameB} processing {input_file}...")
        runB = run_binary(binary_path=buildB, input=input_file, output_dir=targetdir)

        with open(targetdir / f"{nameB}-stdout-raw", "wb") as f:
            f.write(runB.stdout)
        with open(targetdir / f"{nameB}-stderr-raw", "wb") as f:
            f.write(runB.stderr)

        # combined run information
        with open(log, "w") as f:
            f.write(f"{input_file.name} A {nameA} | B {nameB} run output\n--------\n")
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


def get_cflog_entries(tdag, function_id_path):
    """Maps the function ID JSON to the TDAG control flow log."""
    with open(function_id_path) as f:
        function_id = load(f)
    cflog = tdag._get_section(taint_dag.TDControlFlowLogSection)
    cflog.function_id_mapping(list(map(cxxfilt.demangle, function_id)))
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


def compare_cflog(tdagA, tdagB):
    """Once we have annotated the control flow log for each tdag with the separately recorded demangled function names, walk through them and see what does not match."""
    cflogA = get_cflog_entries(tdagA, True)
    cflogB = get_cflog_entries(tdagB, False)

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
        range(len(tdag_a.events)),
        tdag_b.events,
        range(len(tdag_b.events)),
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
    if args.locate:
        print("Locating candidates")
        locate_candidates()
    elif args.tdag_a and args.tdag_b:
        print(f"Comparing {args.tdag_a} and {args.tdag_b}")
        traceA = PolyTrackerTrace.load(args.tdag_a)
        traceB = PolyTrackerTrace.load(args.tdag_b)

        if args.cflog:
            compare_cflog(traceA.tdfile, traceB.tdfile)

        if args.runtrace:
            compare_run_trace(traceA.tdfile, traceB.tdfile)

        if args.inputsused:
            compare_inputs_used(traceA.tdfile, traceB.tdfile)

        if args.enumdiff:
            enum_diff(traceA.tdfile, traceB.tdfile)
    else:
        print("Error: Need to provide either -a and -b, or --locate")
        parser.print_help()
