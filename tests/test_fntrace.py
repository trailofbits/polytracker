import pytest

from collections import defaultdict
from typing import Dict

from polytracker import taint_dag, ProgramTrace

# TODO (hbrodin): Pending integration from other PR

# @pytest.mark.xfail(reason="Pending integration from another PR")
# @pytest.mark.program_trace("test_fntrace.cpp")
# def test_fn_headers(program_trace: ProgramTrace):
#     assert isinstance(program_trace, taint_dag.TDProgramTrace)
#     functions = list(program_trace.tdfile.fn_headers)
#     names = set(map(lambda f: f[0], functions))
#     assert names == set(["main", "_Z9factoriali"])


# @pytest.mark.xfail(reason="Pending integration from another PR")
# @pytest.mark.program_trace("test_fntrace.cpp")
# def test_fntrace(program_trace: ProgramTrace):
#     assert isinstance(program_trace, taint_dag.TDProgramTrace)
#     events = list(program_trace.tdfile.events)
#     assert len(events) == 10
#     kinds: Dict[taint_dag.TDEvent.Kind, int] = defaultdict(int)
#     for e in events:
#         kinds[e.kind] += 1
#     assert kinds[taint_dag.TDEvent.Kind.ENTRY] == kinds[taint_dag.TDEvent.Kind.EXIT]
