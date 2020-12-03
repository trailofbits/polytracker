import argparse
import logging

from .plugins import add_command_subparsers

# the following line imports modules so their commands can register themselves
from . import containerization, datalog, grammars, polytracker

logger = logging.getLogger("polytracker")


def main():
    parser = argparse.ArgumentParser(
        description="PolyTracker can instrument programs to track dataflow and controlflow information through their "
        "execution, and process the resulting traces."
    )

    parser.add_argument("--version", "-v", action="store_true", help="print PolyTracker's version and exit")

    add_command_subparsers(parser)

    args = parser.parse_args()

    if args.version:
        print(polytracker.version())
        exit(0)

    if not hasattr(args, "func"):
        # TODO: Once we implement a REPL, instead of printing help, enter the REPL here
        parser.print_help()
        exit(1)

    return args.func(args)


if __name__ == "__main__":
    main()
