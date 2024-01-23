from argparse import ArgumentParser
import datetime
from pathlib import Path
import subprocess
from typing import List, Set


class Runner:
    def run_binary(
        self, binary_path: Path, arguments: list[str], tstamp: float, instrumented=True
    ):
        """Runs the Polytracker-instrumented binary using the appropriate environment variables. Requires a Polytracker-capable environment, meaning should generally be run in the Polytracker container to avoid having to set up hacked custom LLVM, GLLVM, and friends."""

        if instrumented:
            # instead of producing polytracker.tdag as POLYDB, use the binary name
            env_vars = {
                "POLYDB": f"{binary_path.name}-{tstamp}.tdag",
                "POLYTRACKER_STDOUT_SINK": "1",
                "POLYTRACKER_LOG_CONTROL_FLOW": "1",
            }
        else:
            env_vars = {}

        args = [
            binary_path,
            *arguments,
            f"{binary_path.name}-{tstamp}.out",
        ]
        print(args)
        return subprocess.run(
            args, env=env_vars, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    def output(
        self,
        tstamp: float,
        output_directory: Path,
        binary_buildA: Path,
        binary_buildB: Path,
        filename: Path,
        program_args: List[str] = None,
    ) -> None:
        binary_nameA: str = binary_buildA.name
        binary_nameB: str = binary_buildB.name

        log: Path = output_directory / "log.txt"
        program_args = program_args.append(str(filename.resolve()))
        print(
            f"Sending (A {binary_nameA} | B {binary_nameB}) {program_args} run output to {log.name}..."
        )

        print(f"{binary_nameA} {program_args}...")
        runA = self.run_binary(binary_buildA, program_args, tstamp)

        with open(output_directory / f"{binary_nameA}-stdout-raw", "wb") as f:
            f.write(runA.stdout)
        with open(output_directory / f"{binary_nameA}-stderr-raw", "wb") as f:
            f.write(runA.stderr)

        print(f"{binary_nameB} {program_args}...")
        runB = self.run_binary(binary_buildB, program_args, tstamp)

        with open(output_directory / f"{binary_nameB}-stdout-raw", "wb") as f:
            f.write(runB.stdout)
        with open(output_directory / f"{binary_nameB}-stderr-raw", "wb") as f:
            f.write(runB.stderr)

        # combined run information
        with open(log, "w") as f:
            f.write(
                f"'(A {binary_nameA} | B {binary_nameB}) {program_args}' run output\n--------\n"
            )
            f.write(
                f"{binary_nameA}-stdout(utf-8): {runA.stdout.decode('utf-8')}\n--------\n"
            )
            f.write(
                f"{binary_nameA}-stderr(utf-8): {runA.stderr.decode('utf-8')}\n--------\n"
            )
            f.write(
                f"{binary_nameB}-stdout(utf-8): {runB.stdout.decode('utf-8')}\n--------\n"
            )
            f.write(
                f"{binary_nameB}-stderr(utf-8): {runB.stderr.decode('utf-8')}\n--------\n"
            )

    def run(
        self,
        directory: Path,
        binary_buildA: Path,
        binary_buildB: Path,
        extensions: List[str] = None,
        program_args: List[str] = None,
    ) -> None:
        """Reads a set of file names from stdin and feeds them to both --build_a and --build_b binaries.

        This is the primary driver for testing two binaries. It's possible to test two instrumented differing builds, or an uninstrumented and an instrumented build.
        """
        tstamp: str = datetime.datetime.today().strftime("%Y-%b-%d-%H-%M")

        output_directory = Path(f"./output-{tstamp}")
        output_directory: Path = output_directory.absolute()
        if not output_directory.exists():
            output_directory.mkdir(0o755)

        for filename in directory.iterdir():
            if extensions:
                for ext in extensions:
                    if filename.name.endswith(ext):
                        self.output(
                            tstamp,
                            output_directory,
                            binary_buildA,
                            binary_buildB,
                            filename,
                            program_args,
                        )
                    break
            else:
                self.output(
                    tstamp,
                    output_directory,
                    binary_buildA,
                    binary_buildB,
                    filename,
                    program_args,
                )

    def get_inputs() -> Set[Path]:
        pass


if __name__ == "__main__":
    parser = ArgumentParser(
        prog="runner",
        description="Runs binary builds to produce TDAG traces",
    )
    parser.add_argument(
        "-e",
        "--execute",
        type=str,
        nargs="+",
        help="any command line arguments (including input argument last) to run for each candidate build on each input file in the directory, e.g. ./binary -o foo.png -i",
    )
    parser.add_argument(
        "-d",
        "--directory",
        type=Path,
        required=True,
        nargs="+",
        help="Location(s) of test files (will iterate through these and run both build_a and build_b on them)",
    )
    parser.add_argument(
        "-t",
        "--file_type",
        type=str,
        nargs="+",
        help="The desired file type extension(s). More than one extension can be specified as a comma-sep list. Examples: `-t png`; `-t jpeg,jpg`",
    )
    parser.add_argument(
        "-a",
        "--build_a",
        type=Path,
        required=True,
        help="Path to the first binary build to compare (should be the same software as build b, just built with different options)",
    )
    parser.add_argument(
        "-b",
        "--build_b",
        type=Path,
        required=True,
        help="Path to the second binary build to compare (should be the same software as build a, just built with different options)",
    )
    args = parser.parse_args()
    runner = Runner()

    if args.execute:
        print(
            f"Running {args.build_a} and {args.build_b} with the arguments '{args.execute}' for input files in '{args.directory}'"
        )
    if not args.directory.exists() or not args.directory.is_dir():
        print(
            f"{args.directory} isn't a valid path on this filesystem; please provide a directory of input files"
        )
        parser.print_help()
        exit(1)

    runner.run(args.directory, args.build_a, args.build_b, args.execute)
