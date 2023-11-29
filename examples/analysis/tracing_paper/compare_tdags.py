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


def run(binary_path: Path, filename: Path):
    args = [binary_path, filename]
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def run_instrumented(binary_path: Path, inputfile: Path, targetdir: Path):
    """Runs the Polytracker-instrumented binary using the appropriate environment variables. Requires a Polytracker-capable environment, meaning should generally be run in the Polytracker container to avoid having to set up hacked custom LLVM, GLLVM, and friends."""

    args = [binary_path, inputfile]
    db_name: Path = binary_path.parts[-1]

    e = {
        "POLYDB": str(db_name),
        "POLYTRACKER_STDOUT_SINK": "1",
        "POLYTRACKER_LOG_CONTROL_FLOW": "1",
    }
    ret = subprocess.run(args, env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    rename(db_name, targetdir / db_name)
    return ret


def locate_candidates() -> None:
    for filename in stdin:
        fn = Path(filename.rstrip()).absolute()
        if not fn.exists():
            print(f"Skipping non-existing {fn}.")
            continue

        print(f"Processing: {fn}")

        runA = run(args.tdag_a, fn)
        runB = run(args.tdag_b, fn)
        if runA.stdout != runB.stdout or runA.stderr != runB.stderr:
            targetdir = Path("./output") / fn.name
            targetdir = targetdir.absolute()
            if not targetdir.exists():
                targetdir.mkdir(0o755)
            log = targetdir / "log.txt"

            with open(log, "w") as f:
                f.write(f"FILE: {fn}\n")
                f.write(f"first-stdout(utf-8): {runA.stdout.decode('utf-8')}\n")
                f.write(f"first-stderr(utf-8): {runA.stderr.decode('utf-8')}\n")
                f.write(f"second-stdout(utf-8): {runB.stdout.decode('utf-8')}\n")
                f.write(f"second-stderr(utf-8): {runB.stderr.decode('utf-8')}\n")

            with open(targetdir / "stdout-first-raw", "wb") as f:
                f.write(runA.stdout)
            with open(targetdir / "stdout-second-raw", "wb") as f:
                f.write(runB.stdout)
            with open(targetdir / "stderr-first-raw", "wb") as f:
                f.write(runA.stderr)
            with open(targetdir / "stderr-second-raw", "wb") as f:
                f.write(runB.stderr)

            run_instrumented(args.tdag_a, fn, targetdir)
            run_instrumented(args.tdag_b, fn, targetdir)


def node_equals(n1, n2):
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


def input_offsets(tdf):
    ret = {}
    for input_label in tdf.input_labels():
        node = tdf.decode_node(input_label)
        offset = node.offset
        if offset in ret:
            ret[offset].append(node)
        else:
            ret[offset] = [node]

    # Squash multiple labels at same offset if they are equal
    for k, v in ret.items():
        if all(node_equals(vals, v[0]) for vals in v):
            ret[k] = v[:1]
    return ret


def get_cflog_entries(tdag, function_id_path):
    with open(function_id_path) as f:
        function_id = load(f)
    cflog = tdag._get_section(taint_dag.TDControlFlowLogSection)
    cflog.function_id_mapping(list(map(cxxfilt.demangle, function_id)))
    return list(
        map(
            lambda e: (input_offsets(e.label, tdag), e.callstack),
            filter(lambda e: isinstance(e, taint_dag.TDTaintedControlFlowEvent), cflog),
        )
    )


def print_cols(dbg, release, additional=""):
    print(
        (dbg.ljust(OUTPUT_COLUMN_WIDTH))
        + release.ljust(OUTPUT_COLUMN_WIDTH)
        + additional
    )


def compare_cflog(tdagA, tdagB):
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
            # check if we should be stepping debug or release
            # depending on shortest path
            debug_steps = 0
            release_steps = 0

            while idxA + debug_steps < lenA:
                if cflogA[idxA + debug_steps][0] == entryB[0]:
                    break
                debug_steps += 1

            while idxB + release_steps < lenB:
                if cflogB[idxB + release_steps][0] == entryA[0]:
                    break
                release_steps += 1

            if debug_steps < release_steps:
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
