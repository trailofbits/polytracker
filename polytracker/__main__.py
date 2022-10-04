import sys
import argparse

from .plugins import add_command_subparsers
from . import polytracker


def main():
    parser = argparse.ArgumentParser(
        description=(
            "PolyTracker can instrument programs to track data-flow and control-flow"
            " information through their execution, and process the resulting traces."
        )
    )

    parser.add_argument(
        "--version",
        "-v",
        action="store_true",
        help="print PolyTracker's version and exit",
    )

    add_command_subparsers(parser)

    args = parser.parse_args()

    if not hasattr(args, "func"):
        if args.version:
            print(polytracker.version())
            return 0

        if sys.stdin.isatty() and sys.stdout.isatty():
            from .repl import PolyTrackerREPL

            return PolyTrackerREPL().run()
        else:
            parser.print_help()
            return 1

    retval = args.func(args)
    if retval is None:
        retval = 0
    elif not isinstance(retval, int):
        if retval:
            retval = 0
        else:
            retval = 1

    return retval


if __name__ == "__main__":
    sys.exit(main())
