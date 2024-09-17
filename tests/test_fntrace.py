import pytest

from collections import defaultdict
from pathlib import Path
import subprocess
from typing import Dict

from polytracker import taint_dag, ProgramTrace, PolyTrackerTrace
from polytracker.taint_dag import (
    TDEvent,
    TDEnterFunctionEvent,
    TDLeaveFunctionEvent,
    TDTaintedControlFlowEvent,
)


@pytest.mark.program_trace("test_fntrace.cpp")
def test_fn_headers(program_trace: ProgramTrace):
    assert isinstance(program_trace, taint_dag.TDProgramTrace)
    functions = list(program_trace.tdfile.fn_headers)
    names = set(map(lambda f: f[0], functions))
    assert names == set(["main", "_Z9factoriali"])


@pytest.mark.program_trace("test_fntrace.cpp")
def test_fntrace(instrumented_binary: Path, trace_file: Path):
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

    program_trace = PolyTrackerTrace.load(trace_file)

    assert isinstance(program_trace, taint_dag.TDProgramTrace)

    events: list[TDEvent] = list(program_trace.tdfile.events)
    assert len(events) == 10
    kinds: Dict[taint_dag.TDEvent.Kind, int] = defaultdict(int)
    for e in events:
        kinds[e.kind] += 1
    assert kinds[taint_dag.TDEvent.Kind.ENTRY] == kinds[taint_dag.TDEvent.Kind.EXIT]

    cflog = program_trace.tdfile._get_section(
        taint_dag.TDControlFlowLogSection
    )

    # The functionid mapping is available next to the built binary
    # with open(instrumented_binary.parent / "functionid.json", "rb") as f:
    #     functionid_mapping = list(map(cxxfilt.demangle, json.load(f)))

    # # Apply the id to function mappign
    # cflog.function_id_mapping(functionid_mapping)

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

    for got, expected, event_section_event in zip(cflog, expected_seq, events):
        assert got == expected
        assert got == event_section_event
