import pytest
from polytracker import taint_dag, ProgramTrace, Input
from polytracker.mapping import InputOutputMapping
from typing import cast, Tuple
from pathlib import Path


def input_to_output_path(input: Path) -> Path:
    return Path(str(input) + ".out")


@pytest.mark.program_trace("test_tdag.cpp")
def test_tdfile(program_trace: ProgramTrace):
    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    tdfile = program_trace.tdfile
    assert (
        tdfile.label_count == 14
    )  # 8 source labels, 5 unions/ranges + zero-label (unused)

    t1 = cast(taint_dag.TDSourceNode, tdfile.decode_node(1))
    assert isinstance(t1, taint_dag.TDSourceNode)
    assert t1.affects_control_flow is True

    t2 = cast(taint_dag.TDSourceNode, tdfile.decode_node(2))
    assert isinstance(t2, taint_dag.TDSourceNode)
    assert t2.affects_control_flow is True

    t12 = cast(taint_dag.TDRangeNode, tdfile.decode_node(12))
    assert isinstance(t12, taint_dag.TDRangeNode)
    assert t12.first == 1
    assert t12.last == 4

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

    n12 = tdforest.get_node(12)
    assert n12.parent_labels == (-2, 4)
    assert n12.source is None
    assert n12.affected_control_flow is False
    # Synthetic nodes
    assert tdforest.get_node(-1).parent_labels == (1, 2)
    assert tdforest.get_node(-2).parent_labels == (-1, 3)


@pytest.mark.program_trace("test_tdag.cpp")
def test_input_output_mapping(program_trace_with_path: Tuple[ProgramTrace, Path]):
    program_trace = program_trace_with_path[0]
    input_path = program_trace_with_path[1]
    output_path = input_to_output_path(input_path)
    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    tdfile = program_trace.tdfile

    iomapping = InputOutputMapping(tdfile)
    m = iomapping.mapping()

    # There should be 6 inputs that make it to the output
    assert len(m) == 6

    r2_outputs = {
        (output_path, 0),
        (output_path, 1),
        (output_path, 2),
        (output_path, 3),
    }
    eq_outputs = {(output_path, 4)}

    # Offset zero in input is present in output (via r2 and eq)
    assert (input_path, 0) in m.keys()
    assert m[(input_path, 0)] == r2_outputs.union(eq_outputs)

    # Offsets 1,2,3 in input is present in output (via r2)
    assert (input_path, 1) in m.keys()
    assert m[(input_path, 1)] == r2_outputs
    assert (input_path, 2) in m.keys()
    assert m[(input_path, 2)] == r2_outputs
    assert (input_path, 3) in m.keys()
    assert m[(input_path, 3)] == r2_outputs

    # data[4] (from test_tdag.cpp) written to output
    assert (input_path, 4) in m.keys()
    assert m[(input_path, 4)] == {(output_path, 5)}

    # data[7] is in eq, written to output 4
    assert (input_path, 7) in m.keys()
    assert m[(input_path, 7)] == {(output_path, 4)}


@pytest.mark.program_trace("test_tdag.cpp")
def test_cavity_detection(program_trace_with_path: Tuple[ProgramTrace, Path]):
    program_trace = program_trace_with_path[0]
    input_path = program_trace_with_path[1]
    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    tdfile = program_trace.tdfile

    iomapping = InputOutputMapping(tdfile)
    cav = iomapping.file_cavities()

    assert input_path in cav.keys()
    assert cav[input_path] == [(5, 6), (8, 29)]


@pytest.mark.program_trace("test_tdag.cpp")
def test_inputs(program_trace_with_path: Tuple[ProgramTrace, Path]):
    program_trace = program_trace_with_path[0]
    input_path = program_trace_with_path[1]
    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    inputs = list(program_trace.inputs)
    assert len(inputs) == 1
    assert inputs[0].path == str(input_path)
    # TODO (hbrodin): Should probably not be exposed. Also, the fd is not necessarily unique
    # per run, which is in the documentation for uid.
    assert inputs[0].uid == 4  # stdin, stdout, stderr, tdag-file, input_path
    assert inputs[0].size == 29


@pytest.mark.program_trace("test_tdag.cpp")
def test_output_taints(program_trace_with_path: Tuple[ProgramTrace, Path]):
    program_trace = program_trace_with_path[0]
    input_path = program_trace_with_path[1]
    output_path = input_to_output_path(input_path)
    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    outputs = list(program_trace.output_taints)
    assert len(outputs) == 6
    # The output file
    of = Input(5, str(output_path), 0)

    # First four ouputs have the same label and source, just increase offset
    for i in range(0, 4):
        assert outputs[i].source.uid == of.uid
        assert outputs[i].source.path == of.path
        assert outputs[i].offset == i
        assert outputs[i].label == 12

    # Result of eq
    assert outputs[4].source.uid == of.uid
    assert outputs[4].source.path == of.path
    assert outputs[4].offset == 4
    assert outputs[4].label == 13

    # Result of data[4]
    assert outputs[5].source.uid == of.uid
    assert outputs[5].source.path == of.path
    assert outputs[5].offset == 5
    assert outputs[5].label == 5


@pytest.mark.program_trace("test_tdag.cpp")
def test_inputs_affecting_control_flow(
    program_trace_with_path: Tuple[ProgramTrace, Path]
):
    program_trace = program_trace_with_path[0]
    input_path = program_trace_with_path[1]
    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    taints = program_trace.inputs_affecting_control_flow()
    # Offsets 0,1,6,7 affect control flow
    assert len(taints) == 4
    regions = list(taints.regions())
    assert len(regions) == 2
    assert regions[0].source.path == str(input_path)
    assert regions[0].offset == 0
    assert regions[0].length == 2
    assert regions[1].source.path == str(input_path)
    assert regions[1].offset == 6
    assert regions[1].length == 2


# TODO (hbrodin): Add a test case when the input file size cannot be determined, e.g. stdin
