import sys
import pytest
import subprocess
import polytracker

from pathlib import Path
from typing import List


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
    cmd = ["instrument-targets", target]
    run_polytracker(cmd)


@pytest.fixture
def program_trace(monkeypatch, request):
    marker = request.node.get_closest_marker("program_trace")
    tstdir = Path(request.fspath).parent
    target = tstdir / Path(marker.args[0])
    binary = Path(f"{target.stem}.bin").resolve()
    build(target, binary)
    trace_file = Path(f"{target.stem}.db").resolve()
    trace_file.unlink(missing_ok=True)
    instrument(binary.name)
    monkeypatch.setenv("POLYDB", str(trace_file))
    cmd = [
        # instrumented binary
        Path(f"{binary.stem}.instrumented").resolve(),
        # input data
        str(tstdir / "test_data" / "test_data.txt"),
    ]
    subprocess.check_call(cmd)
    return polytracker.PolyTrackerTrace.load(trace_file)
