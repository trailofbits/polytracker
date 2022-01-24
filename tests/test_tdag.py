import pytest
import logging
from polytracker import tracing, dumptdag
from os import getenv
from tests.tracing import polyclang_compile_target
from .data import *


logger = logging.getLogger("test_plugins:")


def test_basic_tdag_operation():
    target_name = "test_tdag.cpp"
    target_path = TESTS_DIR / target_name
    bin_path = BUILD_DIR / f"{target_name}.bin"

    compile_command = ["/usr/bin/env",
      getenv("CXX"),
      "--instrument-target",
      "--no-control-flow-tracking",
      "-o", to_native_path(bin_path), to_native_path(target_path)]
    assert run_natively(*compile_command) == 0
    assert bin_path.exists()

    data_file = TEST_DATA_DIR / f"{target_name}.txt"

    with open(data_file, "wb") as f:
        f.write(b"abcdefgh")

    run_command = ["/usr/bin/env",
                   bin_path,
                   data_file]

    assert run_natively(*run_command) == 0

    with dumptdag.open_output_file('polytracker.tdag') as o:
      # Basic properties
      assert o.label_count() == 14
      t1 = o.decoded_taint(1)
      assert t1.affects_control_flow == 1

      t2 = o.decoded_taint(2)
      assert t1.affects_control_flow == 1

      t12 = o.decoded_taint(12)
      assert t12.first == 1
      assert t12.last == 4

      assert len(list(o.fd_mappings())) == 2
      assert len(list(o.sink_log())) == 6


      # Cavities
    m = dumptdag.gen_source_taint_used('polytracker.tdag', str(data_file))
    cavities = dumptdag.marker_to_ranges(m)
    assert len(cavities) == 1
    assert cavities[0] == (5,6)