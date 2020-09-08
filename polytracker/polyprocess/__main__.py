import argparse
import logging
import sys

from .. import grammars, tracing
from .polyprocess import PolyProcess

logger = logging.getLogger("polyprocess")


def main():
    parser = argparse.ArgumentParser(
        description="""
    A utility to process the JSON and raw output of 'polytracker' with a
    polytracker.json and a polytracker_forest.bin
    """
    )

    commands = parser.add_mutually_exclusive_group()

    commands.add_argument("--json", "-j", type=str, help="path to polytracker json file")
    parser.add_argument("--forest", "-f", type=str, default=None, help="path to the polytracker forest bin")
    parser.add_argument("--draw-forest", action="store_true", help="produces a taint forest dot file")
    commands.add_argument(
        "--extract-grammar",
        nargs=2,
        action="append",
        metavar=("polytracker_json", "input_file"),
        type=argparse.FileType("rb"),
        help="extract a grammar from the provided pairs of JSON trace files as well as the associated input_file that "
        "was sent to the instrumented parser to generate polytracker_json",
    )
    parser.add_argument("--outfile", type=str, default=None, help="specify outfile JSON path/name")
    parser.add_argument("--debug", "-d", action="store_true", help="enables debug logging")

    args = parser.parse_args(sys.argv[1:])

    if args.debug:
        logger.setLevel(logging.DEBUG)

    draw_forest = args.draw_forest is not None

    if args.draw_forest and args.forest is None:
        sys.stderr.write("Error: Path to forest bin not specified\n\n")
        exit(1)

    if args.forest is not None:
        poly_process = PolyProcess(args.json, args.forest)
        poly_process.process_taint_sets()

        if args.outfile is not None:
            poly_process.set_output_filepath(args.outfile)

        # Output the processed json
        poly_process.output_processed_json()
        # Output optional taint forest diagram
        if draw_forest:
            poly_process.draw_forest()
    elif args.extract_grammar:
        try:
            traces = []
            for json_file, input_file in args.extract_grammar:
                trace = tracing.PolyTrackerTrace.parse(json_file, input_file=input_file)
                if not trace.is_cfg_connected():
                    roots = list(trace.cfg_roots())
                    if len(roots) == 0:
                        sys.stderr.write(f"Error: Basic block trace of {json_file} has no roots!\n\n")
                    else:
                        sys.stderr.write(f"Error: Basic block trace of {json_file} has multiple roots:\n")
                        for r in roots:
                            sys.stderr.write(f"\t{ str(r) }\n")
                        sys.stderr.write("\n")
                    exit(1)
                traces.append(trace)
        except ValueError as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\n\n")
            exit(1)
        print(str(grammars.extract(traces)))


if __name__ == "__main__":
    main()
