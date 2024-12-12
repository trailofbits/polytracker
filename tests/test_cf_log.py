import cxxfilt
import pytest
import subprocess

import polytracker
from pathlib import Path

from polytracker.taint_dag import (
    ControlFlowEvent,
    TDControlFlowLogSection,
    CFEnterFunctionEvent,
    CFLeaveFunctionEvent,
    TaintedControlFlowEvent,
    TDProgramTrace
)
from polytracker import ProgramTrace
from typing import List

@pytest.mark.program_trace("test_fntrace.cpp")
def test_function_mapping(program_trace: ProgramTrace):
    mangled_symbols = list(program_trace.tdfile.mangled_fn_symbol_lookup.values())

    assert mangled_symbols == ["main", "_Z9factoriali"]
    expected_names = ["main", "factorial(int)"]
    for symbol in mangled_symbols:
        assert cxxfilt.demangle(symbol) in expected_names

@pytest.mark.program_trace("test_fntrace.cpp")
def test_callstack_mapping(program_trace: ProgramTrace):
    cflog: TDControlFlowLogSection = program_trace.tdfile.sections_by_type[TDControlFlowLogSection]

    for cflog_entry in cflog:
        assert len(cflog_entry.callstack) > 0
        # a callstack entry (if not mapped and demangled) is just a function id
        for callstack_entry in cflog_entry.callstack:
            # when we look up the function id it should map to a name we traced
            assert callstack_entry in program_trace.tdfile.mangled_fn_symbol_lookup

@pytest.mark.program_trace("test_cf_log.cpp")
def test_cf_log(instrumented_binary: Path, trace_file: Path):
    """Demonstrates how the cflog should work end to end, integrated with the fn mapping and the function symbols from the strings table."""
    # Data to write to stdin, one byte at a time
    stdin_data = "abcdefgh"

    subprocess.run(
        [str(instrumented_binary)],
        input=stdin_data.encode("utf-8"),
        env={
            "POLYDB": str(trace_file),
            "POLYTRACKER_STDIN_SOURCE": "1",
        },
    )

    program_trace = polytracker.PolyTrackerTrace.load(trace_file)

    expected_seq = [
        CFEnterFunctionEvent(["main"]),
        TaintedControlFlowEvent(["main"], 1),
        TaintedControlFlowEvent(["main"], 2),
        TaintedControlFlowEvent(["main"], 3),
        TaintedControlFlowEvent(["main"], 4),
        TaintedControlFlowEvent(["main"], 5),
        TaintedControlFlowEvent(["main"], 6),
        TaintedControlFlowEvent(["main"], 7),
        TaintedControlFlowEvent(["main"], 8),
        TaintedControlFlowEvent(["main"], 15),
        TaintedControlFlowEvent(["main"], 3),
        CFEnterFunctionEvent(["main", "f1(unsigned char)"]),
        TaintedControlFlowEvent(["main", "f1(unsigned char)"], 7),
        CFEnterFunctionEvent(["main", "f1(unsigned char)", "f2(unsigned char)"]),
        TaintedControlFlowEvent(
            ["main", "f1(unsigned char)", "f2(unsigned char)"], 7
        ),
        CFLeaveFunctionEvent(["main", "f1(unsigned char)", "f2(unsigned char)"]),
        CFLeaveFunctionEvent(["main", "f1(unsigned char)"]),
        CFLeaveFunctionEvent(["main"]),  # This is artifical as there is a call to exit
    ]

    cflog: List[ControlFlowEvent] = program_trace.tdfile.cflog(demangle_symbols=True)
    for got, expected in zip(cflog, expected_seq):
        assert got == expected

        if type(got) == TaintedControlFlowEvent:
            assert got.label is not None

        assert len(got.callstack) > 0

    for entry in cflog:
        for callstack_entry in entry.callstack:
            assert callstack_entry in list(program_trace.tdfile.mangled_fn_symbol_lookup.values())