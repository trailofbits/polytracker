import pytest

from polytracker import taint_dag, ProgramTrace
from polytracker.taint_dag import TDSourceNode


@pytest.mark.program_trace("test_offset_read.cpp")
def test_offset_inputs(program_trace: ProgramTrace):
    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    source_labels = [
        program_trace.tdfile.decode_node(label)
        for label in program_trace.tdfile.input_labels()
    ]
    assert len(source_labels) == 2
    assert isinstance(source_labels[0], TDSourceNode)
    assert source_labels[0].offset == 2
    assert isinstance(source_labels[1], TDSourceNode)
    assert source_labels[1].offset == 3
