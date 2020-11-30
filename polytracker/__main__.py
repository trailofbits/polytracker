import argparse
import logging

# the following line imports modules so their commands can register themselves
from . import datalog, grammars
from .polytracker import add_command_subparsers

logger = logging.getLogger("polytracker")


def main():
    parser = argparse.ArgumentParser(
        description="PolyTracker can instrument programs to track dataflow and controlflow information through their "
        "execution, and process the resulting traces."
    )

    add_command_subparsers(parser)

    args = parser.parse_args()

    return args.func(args)


if __name__ == "__main__":
    main()
