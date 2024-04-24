from argparse import ArgumentParser
from functools import partialmethod
from pathlib import Path
from polytracker import PolyTrackerTrace, TDProgramTrace
from analysis import Analysis
from json import load as jsonload
from tqdm import tqdm
import tracemalloc

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
    help="Path to functionid.json function trace for TDAG A (created by polytracker's cflog pass)",
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
    "--verbose",
    help="Use TQDM's descriptive progress bars (this can conflict with showing a cflog, diff, or divergences, so sometimes we want to turn it off)",
    action="store_true",
)

if __name__ == "__main__":
    tracemalloc.start()
    comparator = Analysis()
    args = parser.parse_args()

    if not args.verbose:
        tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)

    if args.tdag_a and args.tdag_b:
        print(f"Comparing {args.tdag_a} and {args.tdag_b}, here we gooooo 🚀")

        traceA: TDProgramTrace = PolyTrackerTrace.load(args.tdag_a, taint_forest=False)
        traceB: TDProgramTrace = PolyTrackerTrace.load(args.tdag_b, taint_forest=False)

        if args.function_id_json_a and args.function_id_json_b and not args.runtrace:
            with open(args.function_id_json_a) as jsonA:
                functions_list_a = jsonload(jsonA)

            with open(args.function_id_json_b) as jsonB:
                functions_list_b = jsonload(jsonB)

            if args.find_divergence:
                snapshot1 = tracemalloc.take_snapshot()
                trace, bytes_operated_from, bytes_operated_to = (
                    comparator.find_divergence(
                        from_tdag=traceA.tdfile,
                        to_tdag=traceB.tdfile,
                        from_functions_list=functions_list_a,
                        to_functions_list=functions_list_b,
                    )
                )
                snapshot2 = tracemalloc.take_snapshot()

                print("[ FIND DIVERGENCES : tracemalloc ]")
                for stat in snapshot2.compare_to(snapshot1, "lineno")[:20]:
                    print(stat)

                comparator.show_divergence(
                    trace, bytes_operated_from, bytes_operated_to, args.input_file
                )

                snapshot3 = tracemalloc.take_snapshot()
                print("[ SHOW DIVERGENCES : tracemalloc ]")
                for stat in snapshot3.compare_to(snapshot2, "lineno")[:20]:
                    print(stat)
            else:
                snapshot1 = tracemalloc.take_snapshot()
                comparator.show_cflog_diff(
                    tdagA=traceA.tdfile,
                    tdagB=traceB.tdfile,
                    functions_list_A=functions_list_a,
                    functions_list_B=functions_list_b,
                    cavities=args.cavities,
                )
                snapshot2 = tracemalloc.take_snapshot()
                print("[ COMPUTE AND SHOW CFLOG DIFF : tracemalloc ]")
                for stat in snapshot2.compare_to(snapshot1, "lineno")[:20]:
                    print(stat)

        # if args.runtrace:
        #     comparator.compare_run_trace(traceA.tdfile, traceB.tdfile, args.cavities)

    elif args.tdag_a and args.function_id_json_a:
        snapshot1 = tracemalloc.take_snapshot()
        trace: TDProgramTrace = PolyTrackerTrace.load(args.tdag_a, taint_forest=False)

        if args.input_file:
            input_file = f"{str(args.tdag_a)} <- {args.input_file}"
        else:
            input_file = str(args.tdag_a)

        snapshot2 = tracemalloc.take_snapshot()
        print("[ LOAD A SINGLE CFLOG : tracemalloc ]")
        for stat in snapshot2.compare_to(snapshot1, "lineno")[:20]:
            print(stat)

        with open(args.function_id_json_a) as json_file:
            functions_list = jsonload(json_file)

        comparator.show_cflog(
            tdag=trace.tdfile,
            function_id_json=functions_list,
            input_file_name=input_file,
            cavities=args.cavities,
        )
        snapshot3 = tracemalloc.take_snapshot()
        print("[ SHOW A SINGLE CFLOG : tracemalloc ]")
        for stat in snapshot3.compare_to(snapshot2, "lineno")[:20]:
            print(stat)
    else:
        print(
            "Error: Need to provide one or two tdags, and corresponding Polytracker-generated function list(s)"
        )
        parser.print_help()
