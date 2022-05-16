import pytest
from polytracker import taint_dag, ProgramTrace
from typing import cast


@pytest.mark.program_trace("test_tdag.cpp")
def test_tdfile(program_trace: ProgramTrace):
    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    tdfile = program_trace.tdfile
    assert tdfile.label_count == 35

    t1 = cast(taint_dag.TDSourceNode, tdfile.decode_node(1))
    assert isinstance(t1, taint_dag.TDSourceNode)
    assert t1.affects_control_flow is True

    t2 = cast(taint_dag.TDSourceNode, tdfile.decode_node(2))
    assert isinstance(t2, taint_dag.TDSourceNode)
    assert t2.affects_control_flow is True

    t33 = cast(taint_dag.TDRangeNode, tdfile.decode_node(33))
    assert isinstance(t33, taint_dag.TDRangeNode)
    assert t33.first == 1
    assert t33.last == 4

    assert len(tdfile.fd_headers) == 2
    assert len(list(tdfile.sinks)) == 6


@pytest.mark.program_trace("test_tdag.cpp")
def test_td_taint_forest(program_trace: ProgramTrace):
    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    tdfile = program_trace.tdfile
    # Basic properties
    tdforest = cast(taint_dag.TDTaintForest, program_trace.taint_forest)
    assert isinstance(tdforest, taint_dag.TDTaintForest)
    assert len(tdforest) == tdfile.label_count
    # Range node unfolding
    nodes = list(tdforest.nodes())
    assert len(nodes) - abs(tdforest.synth_label_cnt) + 1 == tdfile.label_count
    # Basic node properties
    n1 = tdforest.get_node(1)
    assert n1.parent_labels is None
    assert n1.source is not None
    assert n1.affected_control_flow is True

    n2 = tdforest.get_node(2)
    assert n2.parent_labels is None
    assert n2.source is not None
    assert n2.affected_control_flow is True

    n33 = tdforest.get_node(33)
    assert n33.parent_labels == (-2, 4)
    assert n33.source is None
    assert n33.affected_control_flow is False
    # Synthetic nodes
    assert tdforest.get_node(-1).parent_labels == (1, 2)
    assert tdforest.get_node(-2).parent_labels == (-1, 3)
