import argparse
from collections import defaultdict
import subprocess
import os
import sys
from typing import Optional, Set, Iterator, Tuple, Dict
from polytracker import PolyTrackerTrace, taint_dag
from polytracker.taint_dag import TDFile, TDNode, TDSourceNode, TDUnionNode, TDRangeNode
from polytracker.mapping import InputOutputMapping
from pathlib import Path

# To Silence TQDM!
from tqdm import tqdm
from functools import partialmethod

import cxxfilt

tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)


OUTPUT_COLUMN_WIDTH = 40


def build_dir(is_debug):
    if os.environ.get("UBET_BUILD_DIR", "") != "":
        return Path(os.environ["UBET_BUILD_DIR"]) / ["release", "debug"][is_debug]
    else:
        return (
            Path("/polytracker/the_klondike/nitro/build")
            / ["release", "debug"][is_debug]
        )


def instrumented_bin_path(is_debug):
    return build_dir(is_debug) / ["nitro_trackRelease", "nitro_trackDebug"][is_debug]


def bin_path(is_debug):
    return build_dir(is_debug) / ["nitro_Release", "nitro_Debug"][is_debug]


def function_id_path(is_debug):
    return build_dir(is_debug) / "functionid.json"


def db_name(is_debug):
    return ["Release", "Debug"][is_debug] + ".tdag"


LabelType = int
OffsetType = int
FileOffsetType = Tuple[Path, OffsetType]
CavityType = Tuple[OffsetType, OffsetType]


class OutputInputMapping:
    def __init__(self, f: TDFile):
        self.tdfile: TDFile = f

    def dfs_walk(
        self, label: LabelType, seen: Optional[Set[LabelType]] = None
    ) -> Iterator[Tuple[LabelType, TDNode]]:
        if seen is None:
            seen = set()

        stack = [label]
        while stack:
            lbl = stack.pop()

            if lbl in seen:
                continue

            seen.add(lbl)

            n = self.tdfile.decode_node(lbl)

            yield (lbl, n)

            if isinstance(n, TDSourceNode):
                continue

            elif isinstance(n, TDUnionNode):
                stack.append(n.left)
                stack.append(n.right)

            elif isinstance(n, TDRangeNode):
                stack.extend(range(n.first, n.last + 1))

    def mapping(self) -> Dict[FileOffsetType, Set[FileOffsetType]]:
        result: Dict[FileOffsetType, Set[FileOffsetType]] = defaultdict(set)
        for s in list(self.tdfile.sinks):
            for _, n in self.dfs_walk(s.label):
                if isinstance(n, TDSourceNode):
                    sp = self.tdfile.fd_headers[s.fdidx][0]
                    np = self.tdfile.fd_headers[n.idx][0]
                    result[(sp, s.offset)].add((np, n.offset))

        return result


def eq(n1, n2):
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
        if all(eq(vals, v[0]) for vals in v):
            ret[k] = v[:1]
    return ret


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
                if not eq(offset_dbg[i][0], offset_rel[i][0]):
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


def compare_run_trace(tdfdbg, tdfrel):
    # TODO(hbrodin): Just outputing runtrace for release atm.
    for e in tdfrel.events:
        fn = cxxfilt.demangle(tdfdbg.fn_headers[e.fnidx][0])
        print(f"{e}: {fn}")


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


def input_offsets(first_label: int, tdag) -> Set[int]:
    return sorted(map(lambda n: n.offset, input_set(first_label, tdag)))


def run_nitro(is_debug, filename):
    args = [bin_path(is_debug), filename]
    return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def run_instrumented(is_debug: bool, inputfile: Path, targetdir: Path):
    args = [instrumented_bin_path(is_debug), inputfile]
    db = db_name(is_debug)

    e = {
        "POLYDB": str(db),
        "POLYTRACKER_STDOUT_SINK": "1",
        "POLYTRACKER_LOG_CONTROL_FLOW": "1",
    }
    ret = subprocess.run(args, env=e, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    os.rename(db, targetdir / db)


def locate_candindates():
    print("Locating candidates")
    for filename in sys.stdin:
        fn = Path(filename.rstrip()).absolute()
        if not fn.exists():
            print(f"Skipping non-existing {fn}.")
            continue

        print(f"Processing: {fn}")

        dbg = run_nitro(True, fn)
        rel = run_nitro(False, fn)
        if dbg.stdout != rel.stdout or dbg.stderr != rel.stderr:
            targetdir = Path("./output") / fn.name
            targetdir = targetdir.absolute()
            if not targetdir.exists():
                targetdir.mkdir(0o755)
            log = targetdir / "log.txt"

            with open(log, "w") as f:
                f.write(f"FILE: {fn}\n")
                f.write(f"DBG-stdout(utf-8): {dbg.stdout.decode('utf-8')}\n")
                f.write(f"DBG-stderr(utf-8): {dbg.stderr.decode('utf-8')}\n")
                f.write(f"REL-stdout(utf-8): {rel.stdout.decode('utf-8')}\n")
                f.write(f"REL-stderr(utf-8): {rel.stderr.decode('utf-8')}\n")

            with open(targetdir / "stdout-dbg-raw", "wb") as f:
                f.write(dbg.stdout)
            with open(targetdir / "stdout-rel-raw", "wb") as f:
                f.write(rel.stdout)
            with open(targetdir / "stderr-dbg-raw", "wb") as f:
                f.write(dbg.stderr)
            with open(targetdir / "stderr-rel-raw", "wb") as f:
                f.write(rel.stderr)

            run_instrumented(True, fn, targetdir)
            run_instrumented(False, fn, targetdir)


def print_cols(dbg, release, additional=""):
    print(
        (dbg.ljust(OUTPUT_COLUMN_WIDTH))
        + release.ljust(OUTPUT_COLUMN_WIDTH)
        + additional
    )


def compare_cflog(dbg_tdfile, rel_tdfile):
    import json

    def get_cflog_entires(tdfile, is_debug):
        with open(function_id_path(is_debug)) as f:
            function_id = json.load(f)
        cflog = tdfile._get_section(taint_dag.TDControlFlowLogSection)
        cflog.function_id_mapping(list(map(cxxfilt.demangle, function_id)))
        return list(
            map(
                lambda e: (input_offsets(e.label, tdfile), e.callstack),
                filter(
                    lambda e: isinstance(e, taint_dag.TDTaintedControlFlowEvent), cflog
                ),
            )
        )

    dbg = get_cflog_entires(dbg_tdfile, True)
    rel = get_cflog_entires(rel_tdfile, False)

    print("COMPARE CONTROL FLOW LOGS")
    n = max(len(dbg), len(rel))

    len_dbg = len(dbg)
    len_rel = len(rel)

    dbgidx = 0
    relidx = 0
    while dbgidx < len_dbg or relidx < len_rel:
        dbg_entry = dbg[dbgidx] if dbgidx < len_dbg else None
        rel_entry = rel[relidx] if relidx < len_rel else None

        if dbg_entry is None:
            print_cols("", str(rel_entry), "")
            relidx += 1
            continue

        if rel_entry is None:
            print_cols(str(dbg_entry), "", "")
            dbgidx += 1
            continue

        dbg_callstack = str(dbg_entry[1])
        rel_callstack = str(rel_entry[1])

        if dbg_entry[0] == rel_entry[0]:
            print_cols(
                str(dbg_entry[0]),
                str(rel_entry[0]),
                f" !!! DBG: {dbg_callstack} != REL: {rel_callstack}"
                if dbg_callstack != rel_callstack
                else "",
            )
            dbgidx += 1
            relidx += 1
        else:
            # check if we should be stepping debug or release
            # depending on shortest path
            debug_steps = 0
            release_steps = 0

            while dbgidx + debug_steps < len_dbg:
                if dbg[dbgidx + debug_steps][0] == rel_entry[0]:
                    break
                debug_steps += 1

            while relidx + release_steps < len_rel:
                if rel[relidx + release_steps][0] == dbg_entry[0]:
                    break
                release_steps += 1

            if debug_steps < release_steps:
                print_cols(str(dbg_entry[0]), "", dbg_callstack)
                dbgidx += 1
            else:
                print_cols("", str(rel_entry[0]), rel_callstack)
                relidx += 1

    return


def compare_input_output(dbg_tdfile, rel_tdfile):
    dbg_mapping = InputOutputMapping(dbg_tdfile).mapping()
    rel_mapping = InputOutputMapping(rel_tdfile).mapping()
    print("=============== INPUT -> OUTPUT =================")
    keydiff = set(dbg_mapping) - set(rel_mapping)
    print(f"KeyDiff {keydiff}")

    for k_dbg, v_dbg in dbg_mapping.items():
        v_rel = rel_mapping[k_dbg]
        if v_dbg != v_rel:
            print(f"{k_dbg}: DBG {v_dbg} REL {sorted(v_rel)}")


def compare_output_input(dbg_tdfile, rel_tdfile):
    dbg_mapping = OutputInputMapping(dbg_tdfile).mapping()
    rel_mapping = OutputInputMapping(rel_tdfile).mapping()
    print("=============== OUTPUT -> INPUT =================")
    keydiff = set(dbg_mapping) - set(rel_mapping)
    print(f"KeyDiff {keydiff}")

    for k_dbg, v_dbg in dbg_mapping.items():
        v_rel = rel_mapping[k_dbg]
        if v_dbg != v_rel:
            print(f"{k_dbg}: DBG {v_dbg} REL {sorted(v_rel)}")


def do_comparison(path: Path, args):
    dbg_tdag = path / db_name(True)
    rel_tdag = path / db_name(False)
    print(f"Compare {dbg_tdag} and {rel_tdag}")

    dbg_trace = PolyTrackerTrace.load(dbg_tdag)
    rel_trace = PolyTrackerTrace.load(rel_tdag)
    dbg_tdfile = dbg_trace.tdfile
    rel_tdfile = rel_trace.tdfile

    if args.cflog:
        compare_cflog(dbg_tdfile, rel_tdfile)

    if args.inout:
        compare_input_output(dbg_tdfile, rel_tdfile)

    if args.outin:
        compare_output_input(dbg_tdfile, rel_tdfile)

    if args.runtrace:
        compare_run_trace(dbg_tdfile, rel_tdfile)

    if args.inputsused:
        compare_inputs_used(dbg_tdfile, rel_tdfile)

    if args.enumdiff:
        enum_diff(dbg_tdfile, rel_tdfile)


def main():
    parser = argparse.ArgumentParser(
        prog="eval_nitro",
        description="Evaluate unwanted/unexpected/undefined/implementation defined behaviours in Nitro",
    )
    parser.add_argument(
        "-l",
        "--locate",
        action="store_true",
        help="Filenames read from stdin are run in Nitro and any discrepancies between debug/release builds are store in the output directory. Can be executed as 'find dir -type f | python3 eval_nitro.py -l'",
    )
    parser.add_argument(
        "-c",
        "--compare",
        type=Path,
        help="Compare the Debug/Release tdags in the directory.",
    )
    parser.add_argument(
        "--cflog",
        action="store_true",
        help="Compare Control Flow Logs (requires --compare)",
    )
    parser.add_argument(
        "--inout",
        action="store_true",
        help="Compare Input-Output mapping (requires --compare)",
    )
    parser.add_argument(
        "--outin",
        action="store_true",
        help="Compare Output-Input mapping (requires --compare)",
    )
    parser.add_argument(
        "--runtrace", action="store_true", help="Compare runtrace (requires --compare)"
    )
    parser.add_argument(
        "--inputsused",
        action="store_true",
        help="Compare inputs used (requires --compare)",
    )
    parser.add_argument(
        "--enumdiff",
        action="store_true",
        help="Enumerate differences (kind of) (requires --compare)",
    )

    args = parser.parse_args()

    if args.locate and args.compare:
        print("Error: Can both locate and compare")
        parser.print_help()
        return
    elif args.locate:
        locate_candindates()
    elif args.compare:
        do_comparison(args.compare, args)
    else:
        print("Error: Specify either -locate or -compare")
        parser.print_help()


if __name__ == "__main__":
    main()
