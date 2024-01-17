import datetime
from pathlib import Path
import subprocess


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
            "-i",
            *arguments,
            f"-o {binary_path.name}-{tstamp}.out.png",
        ]
        print(args)
        return subprocess.run(
            args, env=env_vars, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )

    def runner(
        self, buildA: Path, buildB: Path, program_args: list[str] = None
    ) -> None:
        """Reads a set of file names from stdin and feeds them to both --build_a and --build_b binaries.

        This is the primary driver for testing two binaries. It's possible to test two instrumented differing builds, or an uninstrumented and an instrumented build.
        """
        nameA: str = buildA.name
        nameB: str = buildB.name

        tstamp: str = datetime.datetime.today().strftime("%Y-%b-%d-%H-%M")

        targetdir = Path(f"./output-{tstamp}")
        targetdir = targetdir.absolute()
        if not targetdir.exists():
            targetdir.mkdir(0o755)
        log = targetdir / "log.txt"
        print(
            f"Sending (A {nameA} | B {nameB}) {program_args} run output to {log.name}..."
        )

        print(f"{nameA} {program_args}...")
        runA = self.run_binary(buildA, program_args, tstamp)

        with open(targetdir / f"{nameA}-stdout-raw", "wb") as f:
            f.write(runA.stdout)
        with open(targetdir / f"{nameA}-stderr-raw", "wb") as f:
            f.write(runA.stderr)

        print(f"{nameB} {program_args}...")
        runB = self.run_binary(buildB, program_args, tstamp)

        with open(targetdir / f"{nameB}-stdout-raw", "wb") as f:
            f.write(runB.stdout)
        with open(targetdir / f"{nameB}-stderr-raw", "wb") as f:
            f.write(runB.stderr)

        # combined run information
        with open(log, "w") as f:
            f.write(f"'(A {nameA} | B {nameB}) {program_args}' run output\n--------\n")
            f.write(f"{nameA}-stdout(utf-8): {runA.stdout.decode('utf-8')}\n--------\n")
            f.write(f"{nameA}-stderr(utf-8): {runA.stderr.decode('utf-8')}\n--------\n")
            f.write(f"{nameB}-stdout(utf-8): {runB.stdout.decode('utf-8')}\n--------\n")
            f.write(f"{nameB}-stderr(utf-8): {runB.stderr.decode('utf-8')}\n--------\n")