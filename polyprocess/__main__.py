import argparse
import logging
import sys

from . import grammars
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
        nargs="+",
        type=argparse.FileType("r"),
        help="extract a grammar from the provided JSON trace files",
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
            traces = [grammars.parse_polytracker_trace(json_file) for json_file in args.extract_grammar]
        except ValueError as e:
            sys.stderr.write(str(e))
            sys.stderr.write("\n\n")
            exit(1)
        grammars.extract(traces)


if __name__ == "__main__":
    main()
