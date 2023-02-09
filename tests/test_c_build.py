import pytest
from polytracker import taint_dag, ProgramTrace


@pytest.mark.program_trace("test_c_build.c")
def test_tdfile(program_trace: ProgramTrace):
    assert isinstance(program_trace, taint_dag.TDProgramTrace)
