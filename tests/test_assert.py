from pathlib import Path
import subprocess
import pytest
from polytracker import taint_dag, PolyTrackerTrace
from typing import cast


@pytest.mark.program_trace("test_assert.cpp")
def test_assert(instrumented_binary: Path, trace_file: Path):
    stdin_data = "ab"

    subprocess.run(
        [str(instrumented_binary)],
        input=stdin_data.encode("utf-8"),
        env={"POLYDB": str(trace_file), "POLYTRACKER_STDIN_SOURCE": str(1)},
    )
    program_trace = PolyTrackerTrace.load(trace_file)
    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    tdfile = program_trace.tdfile
    assert tdfile.label_count == 4

    t1 = cast(taint_dag.TDSourceNode, tdfile.decode_node(1))
    assert isinstance(t1, taint_dag.TDSourceNode)

    t2 = cast(taint_dag.TDSourceNode, tdfile.decode_node(2))
    assert isinstance(t2, taint_dag.TDSourceNode)

    t3 = cast(taint_dag.TDSourceNode, tdfile.decode_node(3))
    assert isinstance(t3, taint_dag.TDRangeNode)
    assert t3.first == 1
    assert t3.last == 2
