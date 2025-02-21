import pytest
import subprocess

import polytracker
from polytracker import taint_dag

from pathlib import Path
from random import choice
from string import printable

# Ensure stdin reads in multiple ways are verified
# examples: getc, fgetc, fread, fread_unlocked, fgetc_unlocked, gets, fgets, getdelim, __getdelim, getw

_stdin_data = '\n'.join(choice(printable) for _ in range(40)).encode("utf-8")

def _run(instrumented_binary: Path, trace_file: Path, method: str) -> None:
    """It's important to split out any DRY from the test framework so it's possible to see when an individual test fails."""
    try:
        subprocess.run(
            args=[str(instrumented_binary), method],
            env={"POLYDB": str(trace_file), "POLYTRACKER_STDIN_SOURCE": "1"},
            stderr=subprocess.STDOUT,
            input=_stdin_data,
            close_fds=False,
            check=True
        )
    except subprocess.CalledProcessError as e:
        # https://docs.python.org/3/library/subprocess.html#subprocess.CalledProcessError.returncode
        print(f"Error code: {e.returncode}")
        print(f"Got back: {e.output}")
        print(f"stdout: {e.stdout}")
        print(f"stderr: {e.stderr}")

def _test_out(program_trace: taint_dag.TDProgramTrace) -> None:
    """Test the resulting tdag program trace, checking its inputs to make sure we worked with tainted stdin"""
    assert "/dev/stdin" in [input.path for input in program_trace.inputs]
    expected_offset = 0
    for input_label in program_trace.tdfile.input_labels():
        src_node = program_trace.tdfile.decode_node(input_label)
        assert isinstance(src_node, polytracker.taint_dag.TDSourceNode)

        # Requires that offsets are ordered according to read
        assert src_node.offset == expected_offset

        # Ensure all source labels originate from stdin
        assert program_trace.tdfile.fd_headers[src_node.idx][0] == Path("/dev/stdin")
        expected_offset += 1

    # Should be as many source labels as the length of stdin_data
    assert expected_offset == len(_stdin_data)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_read(instrumented_binary: Path, trace_file: Path):
    _run(instrumented_binary, trace_file, "read")
    # if running the instrumented binary fails before trace creation, we might have no tdag out.
    program_trace: taint_dag.TDProgramTrace = polytracker.PolyTrackerTrace.load(trace_file)
    _test_out(program_trace)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_fread(instrumented_binary: Path, trace_file: Path):
    _run(instrumented_binary, trace_file, "fread")
    program_trace: taint_dag.TDProgramTrace = polytracker.PolyTrackerTrace.load(trace_file)
    _test_out(program_trace)
    
@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_getc(instrumented_binary: Path, trace_file: Path):
    _run(instrumented_binary, trace_file, "getc")
    program_trace: taint_dag.TDProgramTrace = polytracker.PolyTrackerTrace.load(trace_file)
    _test_out(program_trace)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_getc_unlocked(instrumented_binary: Path, trace_file: Path):
    _run(instrumented_binary, trace_file, "getc_unlocked")
    program_trace: taint_dag.TDProgramTrace = polytracker.PolyTrackerTrace.load(trace_file)
    _test_out(program_trace)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_getchar(instrumented_binary: Path, trace_file: Path):
    _run(instrumented_binary, trace_file, "getchar")
    program_trace: taint_dag.TDProgramTrace = polytracker.PolyTrackerTrace.load(trace_file)
    _test_out(program_trace)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_getchar_unlocked(instrumented_binary: Path, trace_file: Path):
    _run(instrumented_binary, trace_file, "getchar_unlocked")
    program_trace: taint_dag.TDProgramTrace = polytracker.PolyTrackerTrace.load(trace_file)
    _test_out(program_trace)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_fgetc(instrumented_binary: Path, trace_file: Path):
    _run(instrumented_binary, trace_file, "fgetc")
    program_trace: taint_dag.TDProgramTrace = polytracker.PolyTrackerTrace.load(trace_file)
    _test_out(program_trace)
