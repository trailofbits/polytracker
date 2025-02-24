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

def _create_tdag_trace(instrumented_binary: Path, trace_file: Path, method: str) -> None:
    """Rather than using pytest.mark.parametrize on this setup function, split 
    out DRY from the test framework so it's easy to see when an individual test
    fails."""
    # https://docs.python.org/3/library/subprocess.html#subprocess.CalledProcessError.returncode
    subprocess.run(
        args=[str(instrumented_binary), method],
        env={"POLYDB": str(trace_file), "POLYTRACKER_STDIN_SOURCE": "1"},
        stderr=subprocess.STDOUT,
        input=_stdin_data,
        close_fds=False,
    ).check_returncode()

def _test_trace(trace_file: Path) -> None:
    """Test the tdag output, checking its inputs to make sure we tainted and 
    tracked every byte of stdin. Offsets must be ordered as they were read."""
    
    program_trace: taint_dag.TDProgramTrace = polytracker.PolyTrackerTrace.load(trace_file)
    assert "/dev/stdin" in [input.path for input in program_trace.inputs]
    
    expected_offset = 0
    for input_label in program_trace.tdfile.input_labels():
        src_node = program_trace.tdfile.decode_node(input_label)
        assert isinstance(src_node, polytracker.taint_dag.TDSourceNode)
        assert src_node.offset == expected_offset
        assert program_trace.tdfile.fd_headers[src_node.idx][0] == Path("/dev/stdin")
        expected_offset += 1
        
    assert expected_offset == len(_stdin_data)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_read(instrumented_binary: Path, trace_file: Path):
    _create_tdag_trace(instrumented_binary, trace_file, "read")
    _test_trace(trace_file)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_fread(instrumented_binary: Path, trace_file: Path):
    _create_tdag_trace(instrumented_binary, trace_file, "fread")
    _test_trace(trace_file)
    
@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_getc(instrumented_binary: Path, trace_file: Path):
    _create_tdag_trace(instrumented_binary, trace_file, "getc")
    _test_trace(trace_file)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_getc_unlocked(instrumented_binary: Path, trace_file: Path):
    _create_tdag_trace(instrumented_binary, trace_file, "getc_unlocked")
    _test_trace(trace_file)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_getchar(instrumented_binary: Path, trace_file: Path):
    _create_tdag_trace(instrumented_binary, trace_file, "getchar")
    _test_trace(trace_file)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_getchar_unlocked(instrumented_binary: Path, trace_file: Path):
    _create_tdag_trace(instrumented_binary, trace_file, "getchar_unlocked")
    _test_trace(trace_file)

@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin_fgetc(instrumented_binary: Path, trace_file: Path):
    _create_tdag_trace(instrumented_binary, trace_file, "fgetc")
    _test_trace(trace_file)
