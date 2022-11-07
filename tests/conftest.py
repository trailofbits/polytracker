import sys
import pytest
import subprocess
import polytracker

from pathlib import Path
from typing import List


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "program_trace: mark the C/C++ source file to be automatically compiled, instrumented, and run for the test",
    )

    config.addinivalue_line(
        "markers",
        "input_file: provides a input file with known inputs at a random path",
    )


def run_polytracker(cmd: List[str]) -> None:
    tmp = sys.argv
    setattr(sys, "argv", [sys.argv[0], *cmd])
    assert polytracker.main() == 0
    setattr(sys, "argv", tmp)


def build(target: Path, binary: Path) -> None:
    assert target.exists

    cmd = ["build"]
    if target.suffix == ".cpp":
        cmd.append("clang++")
    else:
        cmd.append("clang")

    cmd += ["-g", "-o", str(binary), str(target)]
    run_polytracker(cmd)


def instrument(target: str) -> None:
    cmd = ["instrument-targets", "--taint", "--ftrace", target]
    run_polytracker(cmd)


@pytest.fixture
def input_file(tmp_path):
    # Create a file with input data
    input = tmp_path / "test_data.txt"
    input.write_text("{abcdefgh9jklmnopqrstuvwxyz}\n")
    print(f"Returning {input}")
    return input


@pytest.fixture
def program_trace(input_file, monkeypatch, request):
    # Run everything in a per-test temporary directory
    monkeypatch.chdir(input_file.parent)
    # Build a clean test binary to get a blight journal
    marker = request.node.get_closest_marker("program_trace")
    tstdir = Path(request.fspath).parent
    target = tstdir / Path(marker.args[0])
    binary = Path(f"{target.stem}.bin").resolve()
    build(target, binary)
    # Build an instrumented test binary
    trace_file = Path(f"{target.stem}.db").resolve()
    trace_file.unlink(missing_ok=True)
    instrument(binary.name)
    # Run the instrumented binary to get a trace file
    monkeypatch.setenv("POLYDB", str(trace_file))
    cmd = [
        # instrumented binary
        Path(f"{binary.stem}.instrumented").resolve(),
        # input data
        str(input_file),
    ]
    subprocess.check_call(cmd)
    # Read the trace file
    return polytracker.PolyTrackerTrace.load(trace_file)
