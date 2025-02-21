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


def run_polytracker(cmd: List[str]) -> None:
    tmp = sys.argv
    setattr(sys, "argv", [sys.argv[0], *cmd])
    assert polytracker.main() == 0
    setattr(sys, "argv", tmp)


def build(target: Path, binary: Path) -> None:
    assert target.exists()

    cmd = ["build"]
    if target.suffix == ".cpp":
        cmd += ["clang++", "-std=c++20"]
    else:
        cmd.append("clang")

    # debugging and want symbols? add -O0 here
    cmd += ["-g", "-o", str(binary), str(target)]
    run_polytracker(cmd)


def instrument(target: str) -> None:
    cmd = ["instrument-targets", "--cflog", target]
    run_polytracker(cmd)


@pytest.fixture
def input_file(tmp_path):
    # Create a file with input data
    input = tmp_path / "test_data.txt"
    input.write_text("{abcdefgh9jklmnopqrstuvwxyz}\n")
    return input


@pytest.fixture
def target_source(request):
    """Locates the target source file to instrument"""
    marker = request.node.get_closest_marker("program_trace")
    tstdir = Path(request.fspath).parent
    return tstdir / Path(marker.args[0])


@pytest.fixture
def instrumented_binary(tmp_path, monkeypatch, target_source):
    """Instruments the target source and returns the instrumented binary path"""
    monkeypatch.chdir(tmp_path)
    binary = Path(f"{target_source.stem}.bin").resolve()
    build(target_source, binary)
    instrument(binary.name)
    return Path(f"{binary.stem}.instrumented").resolve()


@pytest.fixture
def trace_file(target_source):
    """Produces a path to the polytracker DB given a target_source"""
    dbpath = Path(f"{target_source.stem}.db").resolve()
    dbpath.unlink(missing_ok=True)
    return dbpath


@pytest.fixture
def program_trace(input_file, trace_file, instrumented_binary, monkeypatch):
    # Run everything in a per-test temporary directory
    monkeypatch.chdir(input_file.parent)
    monkeypatch.setenv("POLYDB", str(trace_file))
    cmd = [
        instrumented_binary,
        str(input_file),
    ]
    subprocess.check_call(cmd)
    return polytracker.PolyTrackerTrace.load(trace_file)
