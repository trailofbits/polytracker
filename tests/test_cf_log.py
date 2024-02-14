import cxxfilt
import json
import pytest
import subprocess

import polytracker
from pathlib import Path

from polytracker.taint_dag import (
    TDEnterFunctionEvent,
    TDLeaveFunctionEvent,
    TDTaintedControlFlowEvent,
)


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

    # The functionid mapping is available next to the built binary
    with open(instrumented_binary.parent / "functionid.json", "rb") as f:
        functionid_mapping = list(map(cxxfilt.demangle, json.load(f)))

    # Apply the id to function mappign
    cflog.function_id_mapping(functionid_mapping)
    assert cflog.funcmapping is not None

    # once funcmapping is available, the __iter__ method should be functional
    assert len(list(cflog)) > 0

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

    # NOTE(hbrodin): Could have done assert list(cflog) == expected_seq, but this provides the failed element
    assert len(list(cflog)) == len(expected_seq)
    for got, expected in zip(cflog, expected_seq):
        assert got == expected


@pytest.mark.program_trace("test_cf_log_recursive.cpp")
def test_cf_log_recursive(instrumented_binary: Path, trace_file: Path):
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

    # The functionid mapping is available next to the built binary
    with open(instrumented_binary.parent / "functionid.json", "rb") as f:
        functionid_mapping = list(map(cxxfilt.demangle, json.load(f)))

    # Apply the id to function mappign
    cflog.function_id_mapping(functionid_mapping)
    assert cflog.funcmapping is not None

    # once funcmapping is available, the __iter__ method should be functional
    assert len(list(cflog)) > 0

    expected_seq = [
        TDEnterFunctionEvent(["main"]),
        TDEnterFunctionEvent(["main", "f1(unsigned char)"]),
        TDEnterFunctionEvent(["main", "f1(unsigned char)", "f1(unsigned char)"]),
        TDEnterFunctionEvent(
            ["main", "f1(unsigned char)", "f1(unsigned char)", "f2(unsigned char)"]
        ),
        TDLeaveFunctionEvent(
            ["main", "f1(unsigned char)", "f1(unsigned char)", "f2(unsigned char)"]
        ),
        TDEnterFunctionEvent(
            ["main", "f1(unsigned char)", "f1(unsigned char)", "f2(unsigned char)"]
        ),
        TDLeaveFunctionEvent(
            ["main", "f1(unsigned char)", "f1(unsigned char)", "f2(unsigned char)"]
        ),
        TDEnterFunctionEvent(
            ["main", "f1(unsigned char)", "f1(unsigned char)", "f1(unsigned char)"]
        ),
        TDTaintedControlFlowEvent(
            ["main", "f1(unsigned char)", "f1(unsigned char)", "f1(unsigned char)"], 4
        ),
        TDEnterFunctionEvent(
            [
                "main",
                "f1(unsigned char)",
                "f1(unsigned char)",
                "f1(unsigned char)",
                "f2(unsigned char)",
            ]
        ),
        TDTaintedControlFlowEvent(
            [
                "main",
                "f1(unsigned char)",
                "f1(unsigned char)",
                "f1(unsigned char)",
                "f2(unsigned char)",
            ],
            4,
        ),
        TDLeaveFunctionEvent(
            [
                "main",
                "f1(unsigned char)",
                "f1(unsigned char)",
                "f1(unsigned char)",
                "f2(unsigned char)",
            ]
        ),
        TDLeaveFunctionEvent(
            ["main", "f1(unsigned char)", "f1(unsigned char)", "f1(unsigned char)"]
        ),
        TDLeaveFunctionEvent(["main", "f1(unsigned char)", "f1(unsigned char)"]),
        TDLeaveFunctionEvent(["main", "f1(unsigned char)"]),
        TDLeaveFunctionEvent(["main"]),
    ]

    assert len(list(cflog)) == len(expected_seq)
    for got, expected in zip(cflog, expected_seq):
        assert got == expected
