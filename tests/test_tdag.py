import pytest
from polytracker import dumptdag, ProgramTrace
from os import getcwd
from .data import TEST_DATA_DIR, TEST_DATA_PATH, TEST_RESULTS_DIR


@pytest.mark.program_trace("test_tdag.cpp")
def test_dumptdag(program_trace: ProgramTrace):
    data_dir = TEST_DATA_DIR.relative_to(getcwd())
    data_file = "/workdir" / data_dir / TEST_DATA_PATH.name
    tdag_file = TEST_RESULTS_DIR / "test_tdag.cpp.db"

    with dumptdag.open_output_file(tdag_file) as o:
        # Basic properties
        assert o.label_count() == 35
        t1 = o.decoded_taint(1)
        assert t1.affects_control_flow == 1

        t2 = o.decoded_taint(2)
        assert t2.affects_control_flow == 1

        t33 = o.decoded_taint(33)
        assert t33.first == 1
        assert t33.last == 4

        assert len(list(o.fd_mappings())) == 2
        assert len(list(o.sink_log())) == 6

    # Cavities
    m = dumptdag.gen_source_taint_used(tdag_file, str(data_file))
    cavities = dumptdag.marker_to_ranges(m)
    assert len(cavities) == 2
    assert cavities[0] == (5, 6)
