import argparse
from .polyprocess import PolyProcess
import logging
import sys

logger = logging.getLogger("polyprocess")


def main():
    parser = argparse.ArgumentParser(
        description="""
    A utility to process the JSON and raw output of 'polytracker' with a
    polytracker.json and a polytracker_forest.bin
    """
    )
    parser.add_argument("--json", "-j", type=str, default=None, help="Path to polytracker json file")
    parser.add_argument("--forest", "-f", type=str, default=None, help="Path to the polytracker forest bin")
    parser.add_argument("--debug", "-d", action="store_true", default=None, help="Enables debug logging")
    parser.add_argument("--draw-forest", action="store_true", default=None, help="Produces a taint forest dot file")
    parser.add_argument("--outfile", type=str, default=None, help="Specify outfile JSON path/name")

    args = parser.parse_args(sys.argv[1:])

    if args.debug:
        logger.setLevel(logging.DEBUG)

    draw_forest = args.draw_forest is not None

    if args.json is None:
        print("Error: Path to JSON not specified")
        return
    if args.forest is None:
        print("Error: Path to forest bin not specified")
        return

    poly_process = PolyProcess(args.json, args.forest)
    poly_process.process_taint_sets()

    if args.outfile is not None:
        poly_process.set_output_filepath(args.outfile)

    # Output the processed json
    poly_process.output_processed_json()
    # Output optional taint forest diagram
    if draw_forest:
        poly_process.draw_forest()


if __name__ == "__main__":
    main()
