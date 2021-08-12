import argparse
import subprocess
import sys
from typing import Optional

from .containerization import CAN_RUN_NATIVELY, DockerContainer, DockerRun
from .plugins import Command


class PolyBuild(Command):
    name = "build"
    help = "runs `polybuild`: clang with PolyTracker instrumentation enabled"
    _container: Optional[DockerContainer] = None

    def __init_arguments__(self, parser: argparse.ArgumentParser):
        parser.add_argument("--c++", action="store_true", help="run polybuild++ in C++ mode")
        parser.add_argument("args", nargs=argparse.REMAINDER)

    def run(self, args: argparse.Namespace):
        if getattr(args, "c++", False):
            cmd = "polybuild_script++"
        else:
            cmd = "polybuild_script"
            # Are we trying to compile C++ code without using `polybuild++`?
            if sys.stderr.isatty() and sys.stdin.isatty() and any(
                    arg.strip()[-4:].lower() in (".cpp", ".cxx", ".c++") for arg in args.args
            ):
                # one of the arguments ends in .cpp, .cxx, or .c++
                sys.stderr.write("It looks like you are trying to compile C++ code.\n"
                                 "This requires `polybuild++`, not `polybuild`!\n")
                while True:
                    sys.stderr.write(f"Would you like to run with `polybuild++` instead? [Yn] ")
                    try:
                        choice = input().lower()
                    except KeyboardInterrupt:
                        exit(1)
                    if choice == "n":
                        break
                    elif choice == "y" or choice == "":
                        cmd = "polybuild_script++"
                        break
        args = [cmd] + args.args
        if CAN_RUN_NATIVELY:
            return subprocess.call(args)  # type: ignore
        else:
            if self._container is None:
                self._container = DockerContainer()
            return DockerRun.run_on(self._container, args, interactive=False)


class PolyInst(Command):
    name = "lower"
    help = "runs `polybuild` --lower-bitcode"
    _container: Optional[DockerContainer] = None

    def __init_arguments__(self, parser: argparse.ArgumentParser):
        parser.add_argument("--input-file", type=str, help="input bitcode file")
        parser.add_argument("--output-file", type=str, help="output bitcode file")

    def run(self, args: argparse.Namespace):
        cmd = "polybuild_script"
        items = [cmd] + ["--lower-bitcode", "-i", args.input_file, "-o", args.output_file]
        if CAN_RUN_NATIVELY:
            return subprocess.call(items)
        else:
            if self._container is None:
                self._container = DockerContainer()
            return DockerRun.run_on(self._container, items, interactive=False)


def main():
    PolyBuild(argparse.ArgumentParser(add_help=False)).run(argparse.Namespace(args=sys.argv[1:], **{"c++": False}))


def main_plus_plus():
    PolyBuild(argparse.ArgumentParser(add_help=False)).run(argparse.Namespace(args=sys.argv[1:], **{"c++": True}))
