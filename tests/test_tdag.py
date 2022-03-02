import pytest
from polytracker import dumptdag, taint_dag, ProgramTrace
from os import getcwd
from typing import cast
from .data import TEST_DATA_DIR, TEST_DATA_PATH, TEST_RESULTS_DIR


@pytest.mark.program_trace("test_tdag.cpp")
def test_dumptdag(program_trace: ProgramTrace):
    data_dir = TEST_DATA_DIR.relative_to(getcwd())
    data_file = "/workdir" / data_dir / TEST_DATA_PATH.name
    tdag_file = TEST_RESULTS_DIR / "test_tdag.cpp.db"

    with dumptdag.open_output_file(tdag_file) as o:
        # Basic properties
        assert o.label_count() == 35
        t1 = o.decoded_taint(1)
        assert t1.affects_control_flow == 1

        t2 = o.decoded_taint(2)
        assert t2.affects_control_flow == 1

        t33 = o.decoded_taint(33)
        assert t33.first == 1
        assert t33.last == 4

        assert len(list(o.fd_mappings())) == 2
        assert len(list(o.sink_log())) == 6

    # Cavities
    m = dumptdag.gen_source_taint_used(tdag_file, data_file)
    cavities = dumptdag.marker_to_ranges(m)
    assert len(cavities) == 2
    assert cavities[0] == (5, 6)


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