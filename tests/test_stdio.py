import pytest

from pathlib import Path
from polytracker import taint_dag, ProgramTrace


@pytest.fixture
def set_env_vars(monkeypatch):
    monkeypatch.setenv("POLYTRACKER_STDOUT_SINK", "1")
    monkeypatch.setenv("POLYTRACKER_STDERR_SINK", "1")


@pytest.mark.program_trace("test_stdio.cpp")
def test_stdio(set_env_vars, program_trace: ProgramTrace):
    assert isinstance(program_trace, taint_dag.TDProgramTrace)
    stdout = Path("/dev/stdout")
    stderr = Path("/dev/stderr")
    headers = list(program_trace.tdfile.fd_headers)
    paths = list(map(lambda h: h[0], headers))
    assert len(paths) == 3
    assert stdout in paths
    assert stderr in paths
    sinks = list(program_trace.tdfile.sinks)
    assert len(sinks) == 2
    assert paths[sinks[0].fdidx] == stdout
    assert paths[sinks[1].fdidx] == stderr
