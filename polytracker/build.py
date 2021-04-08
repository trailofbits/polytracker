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
        parser.add_argument(
            "--c++", action="store_true", help="run polybuild++ in C++ mode"
        )
        parser.add_argument("args", nargs=argparse.REMAINDER)

    def run(self, args: argparse.Namespace):
        if getattr(args, "c++"):
            cmd = "polybuild_script++"
        else:
            cmd = "polybuild_script"
        args = [cmd] + args.args
        if CAN_RUN_NATIVELY:
            return subprocess.call(args)  # type: ignore
        else:
            if self._container is None:
                self._container = DockerContainer()
            return DockerRun.run_on(self._container, args, interactive=False)


def main():
    PolyBuild(argparse.ArgumentParser(add_help=False)).run(
        argparse.Namespace(args=sys.argv[1:], **{"c++": False})
    )


def main_plus_plus():
    PolyBuild(argparse.ArgumentParser(add_help=False)).run(
        argparse.Namespace(args=sys.argv[1:], **{"c++": True})
    )
