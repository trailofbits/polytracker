import pytest
import subprocess

import polytracker
from pathlib import Path


@pytest.mark.program_trace("test_stdin.cpp")
@pytest.mark.parametrize(
    "method",
    ["read", "fread", "getc", "getc_unlocked", "getchar", "getchar_unlocked", "fgetc"],
)
def test_stdin_read(instrumented_binary: Path, trace_file: Path, method: str):
    # Data to write to stdin, one byte at a time
    stdin_data = "abcdefghi\njklmnopqr"

    subprocess.run(
        [str(instrumented_binary), method],
        input=stdin_data.encode("utf-8"),
        env={"POLYDB": str(trace_file), "POLYTRACKER_STDIN_SOURCE": str(1)},
    )
    program_trace = polytracker.PolyTrackerTrace.load(trace_file)

    print(program_trace)
    for inp in program_trace.inputs:
        print(inp)
    for lbl in program_trace.tdfile.input_labels():
        print(f"lbl {lbl} decoded {program_trace.tdfile.decode_node(lbl)}")

    # Ensure /dev/stdin is in the list of inputs
    assert "/dev/stdin" in [x.path for x in program_trace.inputs]

    n = 0
    for input_label in program_trace.tdfile.input_labels():
        src_node = program_trace.tdfile.decode_node(input_label)
        assert isinstance(src_node, polytracker.taint_dag.TDSourceNode)

        # Requires that offsets are ordered according to read
        assert src_node.offset == n

        # Ensure all source labels originate from stdin
        assert program_trace.tdfile.fd_headers[src_node.idx][0] == Path("/dev/stdin")
        n += 1

    # Should be as many source labels as the length of stdin_data
    assert n == len(stdin_data)


# Ensure stdin reads in multiple ways are verified
# examples: getc, fgetc, fread, fread_unlocked, fgetc_unlocked, gets, fgets, getdelim, __getdelim, getw
