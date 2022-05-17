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
        parser.add_argument("args", nargs=argparse.REMAINDER)

    def run(self, args: argparse.Namespace):
        cmd = "polybuild_script"
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
        items = [cmd] + [
            "--lower-bitcode",
            "-i",
            args.input_file,
            "-o",
            args.output_file,
        ]
        if CAN_RUN_NATIVELY:
            return subprocess.call(items)
        else:
            if self._container is None:
                self._container = DockerContainer()
            return DockerRun.run_on(self._container, items, interactive=False)


def main():
    PolyBuild(argparse.ArgumentParser(add_help=False)).run(
        argparse.Namespace(args=sys.argv[1:])
    )
