import pytest

from pathlib import Path
from polytracker import taint_dag, ProgramTrace


@pytest.fixture
def set_env_vars(monkeypatch):
    monkeypatch.setenv("POLYTRACKER_TAINT_ARGV", "1")


@pytest.mark.program_trace("test_argv.cpp", input="any")
def test_argv(set_env_vars, program_trace: ProgramTrace):
    assert isinstance(program_trace, taint_dag.TDProgramTrace)
    argv0 = Path("argv[0]")
    argv1 = Path("argv[1]")
    headers = list(program_trace.tdfile.fd_headers)
    paths = list(map(lambda h: h[0], headers))
    assert len(paths) == 3
    assert argv0 in paths
    assert argv1 in paths

    sinks = list(program_trace.tdfile.sinks)

    with open("outputfile.txt", "r") as f:
        output = f.read()

    assert len(output) == len(sinks)

    last_fdidx = 0
    last_offset = 0
    for s in sinks:
        sink_fd_idx = s.fdidx
        label = s.label

        n = program_trace.tdfile.decode_node(label)
        # No transformation/union of argv is made
        assert isinstance(n, taint_dag.TDSourceNode)

        # If we just stepped to the next taint source, reset the offset
        if last_fdidx != n.idx:
            last_offset = 0

        # First write argv[0], then argv[1], ...
        assert last_fdidx <= n.idx

        # Write argv[x], all offsets
        assert last_offset <= n.offset

        # Source file indices for argv[x] are opened before output file
        assert n.idx < sink_fd_idx

        last_offset = n.offset
        last_fdidx = n.idx
