from analysis import Analysis
from argparse import ArgumentParser
import cxxfilt
from functools import partialmethod
import json
from os import environ
from pathlib import Path
from polytracker import PolyTrackerTrace, TDProgramTrace
from tqdm import tqdm
import tracemalloc
from typing import List

parser = ArgumentParser(
    prog="compare_tdags",
    description="Compares TDAGs",
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
    help="Path to DEMANGLED functionid.json function trace for TDAG A (created by polytracker's cflog pass, and previously demangled with --demangle)",
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
    help="Path to the DEMANGLED functionid.json function trace for TDAG (use --demangle to get readable names from the recorded LLVM symbols)",
)
# parser.add_argument(
#     "--runtrace", action="store_true", help="Compare runtrace (requires -a and -b)"
# )
parser.add_argument(
    "--cavities",
    help="Contextualize input trace(s) with blind spots (dont-care bytes)",
    action="store_true",
)
parser.add_argument(
    "--find_divergence",
    "-d",
    action="store_true",
    help="Find the point(s) in the trace where " "divergences occurred",
)
parser.add_argument(
    "--input_file",
    "-f",
    type=Path,
    default=None,
    help="Path to the input file used to generate the " "TDAGs (optional)",
)
parser.add_argument(
    "--demangle",
    "-dm",
    type=Path,
    default=None,
    help="Accepts a static functionid.json set of symbols produced during software instrumentation, writes out the demangled version of the file to demangled_functionid.json in the local working directory",
)
parser.add_argument(
    "--verbose",
    help="Use TQDM's descriptive progress bars (this can conflict with showing a cflog, diff, or divergences, so sometimes we want to turn it off). May not silence TQDM usage in dependencies like Graphtage.",
    action="store_true",
)
parser.add_argument(
    "--memory",
    "-m",
    help="Show top level tracemalloc statistics (do not use at the same time as --timing as they will conflict)",
    action="store_true",
)

if __name__ == "__main__":
    tracemalloc.start()
    comparator = Analysis()
    args = parser.parse_args()

    if not args.verbose:
        environ["TQDM_DISABLE"] = "1"
        tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)

    if args.demangle:
        # you can also use llvm-cxxfile to demangle the function lists
        print(f"Demangling {args.demangle}...")
        with open(args.demangle) as jsonA:
            functions_list = json.load(jsonA)
        demangled_functions_list: List[str] = []
        for function in functions_list:
            try:
                demangled_functions_list.append(cxxfilt.demangle(function))
            except cxxfilt.InvalidName:
                # if we can't demangle it, just keep the opaque name
                demangled_functions_list.append(function)
        output_name = f"demangled_{Path(args.demangle).name}"
        if not Path.exists(Path(output_name)):
            with open(output_name, "w") as output:
                to_write = json.dumps(demangled_functions_list)
                output.write(to_write)
            print(
                f"Wrote demangled symbols to {output_name} in the current working directory! Bye!"
            )
        else:
            print(
                f"Oh no! There's already a file called {output_name} in the working directory; please rename or move that and try again..."
            )
        exit
    elif args.tdag_a and args.tdag_b:
        print(f"Comparing {args.tdag_a} and {args.tdag_b}, here we gooooo 🚀")

        traceA: TDProgramTrace = PolyTrackerTrace.load(args.tdag_a, taint_forest=False)
        traceB: TDProgramTrace = PolyTrackerTrace.load(args.tdag_b, taint_forest=False)

        if args.function_id_json_a and args.function_id_json_b:
            with open(args.function_id_json_a) as jsonA:
                functions_list_a = json.load(jsonA)

            with open(args.function_id_json_b) as jsonB:
                functions_list_b = json.load(jsonB)

            if args.find_divergence:

                if args.memory:
                    snapshot1 = tracemalloc.take_snapshot()

                trace, bytes_operated_from, bytes_operated_to = (
                    comparator.find_divergence(
                        from_tdag=traceA.tdfile,
                        to_tdag=traceB.tdfile,
                        from_functions_list=functions_list_a,
                        to_functions_list=functions_list_b,
                    )
                )

                if args.memory:
                    snapshot2 = tracemalloc.take_snapshot()
                    print("[ FIND DIVERGENCES : tracemalloc ]")
                    for stat in snapshot2.compare_to(snapshot1, "lineno")[:20]:
                        print(stat)

                comparator.show_divergence(
                    trace, bytes_operated_from, bytes_operated_to, args.input_file
                )

                if args.memory:
                    snapshot3 = tracemalloc.take_snapshot()
                    print("[ SHOW DIVERGENCES : tracemalloc ]")
                    for stat in snapshot3.compare_to(snapshot2, "lineno")[:20]:
                        print(stat)
            else:
                if args.memory:
                    snapshot1 = tracemalloc.take_snapshot()

                comparator.show_cflog_diff(
                    tdagA=traceA.tdfile,
                    tdagB=traceB.tdfile,
                    functions_list_A=functions_list_a,
                    functions_list_B=functions_list_b,
                    cavities=args.cavities,
                )

                if args.memory:
                    snapshot2 = tracemalloc.take_snapshot()
                    print("[ COMPUTE AND SHOW CFLOG DIFF : tracemalloc ]")
                    for stat in snapshot2.compare_to(snapshot1, "lineno")[:20]:
                        print(stat)

        # if args.runtrace:
        #     comparator.compare_run_trace(traceA.tdfile, traceB.tdfile, args.cavities)

    elif args.tdag_a and args.function_id_json_a:

        if args.memory:
            snapshot1 = tracemalloc.take_snapshot()

        trace: TDProgramTrace = PolyTrackerTrace.load(args.tdag_a, taint_forest=False)

        if args.input_file:
            input_file = f"{str(args.tdag_a)} <- {args.input_file}"
        else:
            input_file = str(args.tdag_a)

        if args.memory:
            snapshot2 = tracemalloc.take_snapshot()
            print("[ LOAD A SINGLE CFLOG : tracemalloc ]")
            for stat in snapshot2.compare_to(snapshot1, "lineno")[:20]:
                print(stat)

        with open(args.function_id_json_a) as json_file:
            functions_list = json.load(json_file)

        comparator.show_cflog(
            tdag=trace.tdfile,
            function_id_json=functions_list,
            input_file_name=input_file,
            cavities=args.cavities,
        )

        if args.memory:
            snapshot3 = tracemalloc.take_snapshot()
            print("[ SHOW A SINGLE CFLOG : tracemalloc ]")
            for stat in snapshot3.compare_to(snapshot2, "lineno")[:20]:
                print(stat)
    else:
        print(
            "Error: Need to provide one or two tdags, and corresponding Polytracker-generated function list(s)"
        )
        parser.print_help()
