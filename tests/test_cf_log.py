import cxxfilt
import pytest
import subprocess

import polytracker
from pathlib import Path

from polytracker.taint_dag import (
    # TDEvent,
    TDControlFlowLogSection,
    TDEnterFunctionEvent,
    TDLeaveFunctionEvent,
    TDTaintedControlFlowEvent,
    TDProgramTrace
)
from polytracker import ProgramTrace
from typing import List

@pytest.mark.program_trace("test_fntrace.cpp")
def test_cf_log_fn_trace(program_trace: ProgramTrace):
    assert isinstance(program_trace, TDProgramTrace)

    # we store the names in llvm mangled fashion but...
    assert program_trace.tdfile.fn_headers == ["main", "_Z9factoriali"]

    # you can easily unmangle them for human readable stack traces!
    functionid_mapping: List[str] = list(map(cxxfilt.demangle, program_trace.tdfile.fn_headers))
    assert functionid_mapping == ["main", "factorial(int)"]
