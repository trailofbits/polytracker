import pytest
import subprocess

import polytracker
from pathlib import Path


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
    assert 10 == len(cflog)
    assert [1, 2, 3, 4, 5, 6, 7, 8, 15, 3] == list(cflog)
