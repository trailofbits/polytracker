import pytest
import subprocess

import polytracker
from pathlib import Path


@pytest.fixture
def stdin_source_env_vars(monkeypatch):
    monkeypatch.setenv("POLYTRACKER_STDIN_SOURCE", "1")


@pytest.mark.program_trace("test_stdin.cpp")
def test_stdin(instrumented_binary: Path, trace_file: Path, stdin_source_env_vars):
    # Data to write to stdin, one byte at a time
    stdin_data = "abcdefghijklmnopqr"
    skip_byte = 1

    proc = subprocess.run(
        [str(instrumented_binary), str(skip_byte)],
        input=stdin_data.encode("utf-8"),
        env={"POLYDB": trace_file},
    )
    program_trace = polytracker.PolyTrackerTrace.load(trace_file)

    n = 0
    for input_label in program_trace.tdfile.input_labels():
        src_node = program_trace.tdfile.decode_node(input_label)
        assert isinstance(src_node, polytracker.taint_dag.TDSourceNode)
        assert (
            src_node.offset == n
        )  # Requires that offsets are ordered according to read
        # Ensure all source labels originate from stdin
        assert program_trace.tdfile.fd_headers[src_node.idx][0] == Path("/dev/stdin")
        n += 1

    # Should be as many source labels as the length of stdin_data
    assert n == len(stdin_data)
