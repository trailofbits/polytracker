import cxxfilt
import pytest
import subprocess

import polytracker
from pathlib import Path

from polytracker.taint_dag import (
    Event,
    TDEnterFunctionEvent,
    TDLeaveFunctionEvent,
    TDTaintedControlFlowEvent,
    TDProgramTrace
)
from polytracker import ProgramTrace

@pytest.mark.program_trace("test_fntrace.cpp")
def test_cf_log_fn_trace(program_trace: ProgramTrace):
    assert isinstance(program_trace, TDProgramTrace)

    functions = list(program_trace.tdfile.fn_headers)
    names = set(map(lambda f: f[0], functions))
    # we store the names in llvm mangled fashion but
    assert names == set(["main", "_Z9factoriali"])

    # you can easily unmangle them for readability!
    functionid_mapping = list(map(cxxfilt.demangle, functions))
    assert functionid_mapping == set(["main", "factorial(int)"])

@pytest.mark.program_trace("test_cf_log.cpp")
def test_cf_log(instrumented_binary: Path, trace_file: Path):
    # Data to write to stdin, one byte at a time
    stdin_data = "abcdefgh"

    subprocess.run(
        [str(instrumented_binary)],
        input=stdin_data.encode("utf-8"),
        env={
            "POLYDB": str(trace_file),
            "POLYTRACKER_STDIN_SOURCE": "1",
            "POLYTRACKER_LOG_CONTROL_FLOW": "1",
        },
    )

    program_trace = polytracker.PolyTrackerTrace.load(trace_file)

    cflog = program_trace.tdfile._get_section(
        polytracker.taint_dag.TDControlFlowLogSection
    )

    functions = program_trace.tdfile.fn_headers

    functionid_mapping = list(map(cxxfilt.demangle, functions))

    # Apply the id to function mapping
    cflog.function_id_mapping(functionid_mapping)

    expected_seq = [
        TDEnterFunctionEvent(["main"]),
        TDTaintedControlFlowEvent(["main"], 1),
        TDTaintedControlFlowEvent(["main"], 2),
        TDTaintedControlFlowEvent(["main"], 3),
        TDTaintedControlFlowEvent(["main"], 4),
        TDTaintedControlFlowEvent(["main"], 5),
        TDTaintedControlFlowEvent(["main"], 6),
        TDTaintedControlFlowEvent(["main"], 7),
        TDTaintedControlFlowEvent(["main"], 8),
        TDTaintedControlFlowEvent(["main"], 15),
        TDTaintedControlFlowEvent(["main"], 3),
        TDEnterFunctionEvent(["main", "f1(unsigned char)"]),
        TDTaintedControlFlowEvent(["main", "f1(unsigned char)"], 7),
        TDEnterFunctionEvent(["main", "f1(unsigned char)", "f2(unsigned char)"]),
        TDTaintedControlFlowEvent(
            ["main", "f1(unsigned char)", "f2(unsigned char)"], 7
        ),
        TDLeaveFunctionEvent(["main", "f1(unsigned char)", "f2(unsigned char)"]),
        TDLeaveFunctionEvent(["main", "f1(unsigned char)"]),
        TDLeaveFunctionEvent(["main"]),  # This is artifical as there is a call to exit
    ]

    assert len(got) > 0

    for got, expected in zip(cflog, expected_seq):
        assert type(got) == Event
        assert got == expected
        if type(got) == TDTaintedControlFlowEvent:
            # inheritance should make this work?
            assert got.label is not None
