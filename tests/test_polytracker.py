import os
import pytest
import shutil
import subprocess

from .data import *
from .test_polyprocess import test_polyprocess_taint_sets


"""
Pytest fixture to init testing env (building tests) 

This runs before any test is executed
"""


@pytest.fixture(scope="session", autouse=True)
def setup_targets():
    # Check if bin dir exists
    if BIN_DIR.exists():
        shutil.rmtree(BIN_DIR)
    BIN_DIR.mkdir()
    if TEST_RESULTS_DIR.exists():
        shutil.rmtree(TEST_RESULTS_DIR)
    TEST_RESULTS_DIR.mkdir()
    if BITCODE_DIR.exists():
        shutil.rmtree(BITCODE_DIR)
    BITCODE_DIR.mkdir()
    if IS_LINUX:
        target_files = [f for f in os.listdir(TEST_DATA_DIR) if f.endswith(".c") or f.endswith(".cpp")]
        for file in target_files:
            assert polyclang_compile_target(file) == 0


def polyclang_compile_target(target_name: str) -> int:
    is_cxx: bool = False
    if target_name.endswith(".cpp"):
        is_cxx = True
    if is_cxx:
        cxx = os.getenv("CXX")
        if cxx is None:
            print("Error! Could not find CXX")
            return -1
        compile_command = [
            cxx,
            "--instrument-target",
            "-g",
            "-o",
            BIN_DIR / f"{target_name}.bin",
            TEST_DATA_DIR / target_name,
        ]
        ret_val = subprocess.call(compile_command)
    else:
        cc = os.getenv("CC")
        if cc is None:
            print("Error! Could not find CC")
            return -1
        compile_command = [
            cc,
            "--instrument-target",
            "-g",
            "-o",
            BIN_DIR / f"{target_name}.bin",
            TEST_DATA_DIR / target_name,
        ]
        ret_val = subprocess.call(compile_command)
    return ret_val


# Returns the Polyprocess object
def validate_execute_target(target_name):
    target_bin_path = BIN_DIR / f"{target_name}.bin"
    assert target_bin_path.exists()
    os.environ["POLYPATH"] = str(TEST_DATA_PATH)
    os.environ["POLYOUTPUT"] = str(TEST_RESULTS_DIR / target_name)
    ret_val = subprocess.call([target_bin_path, TEST_DATA_PATH])
    assert ret_val == 0
    # Assert that the appropriate files were created
    forest_path = TEST_RESULTS_DIR / f"{target_name}0_forest.bin"
    # Add the 0 here for thread counting.
    json_path = TEST_RESULTS_DIR / f"{target_name}0_process_set.json"
    assert forest_path.exists()
    assert json_path.exists()
    pp = PolyProcess(json_path, forest_path)
    pp.process_taint_sets()
    return pp


@only_linux
def test_source_mmap():
    target_name = "test_mmap.c"
    # Find and run test
    pp = validate_execute_target(target_name)
    mmap_processed_sets = pp.processed_taint_sets
    # Confirm that main touched tainted byte 0
    assert 0 in mmap_processed_sets["main"]["input_bytes"][TEST_DATA_PATH]


@only_linux
def test_source_open():
    target_name = "test_open.c"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    open_processed_sets = pp.processed_taint_sets
    assert 0 in open_processed_sets["main"]["input_bytes"][TEST_DATA_PATH]


@only_linux
def test_source_open_full_validate_schema():
    target_name = "test_open.c"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    forest_path = os.path.join(TEST_RESULTS_DIR, target_name + "0_forest.bin")
    json_path = os.path.join(TEST_RESULTS_DIR, target_name + "0_process_set.json")
    open_processed_sets = pp.processed_taint_sets
    assert 0 in open_processed_sets["main"]["input_bytes"][test_filename]
    test_polyprocess_taint_sets(json_path, forest_path)


@only_linux
def test_memcpy_propagate():
    target_name = "test_memcpy.c"
    pp = validate_execute_target(target_name)
    raw_taint_sets = pp.taint_sets
    assert 1 in raw_taint_sets["dfs$touch_copied_byte"]["input_bytes"]


@only_linux
def test_taint_log():
    target_name = "test_taint_log.c"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    log_processed_sets = pp.processed_taint_sets
    for i in range(0, 10):
        assert i in log_processed_sets["main"]["input_bytes"][test_filename]


# This is a bad name for this test
# This test compares the taint sources info with the tainted block info
# When reading an entire file in a single block
# Basically make sure the start/end match to prevent off-by-one errors
# TODO
@only_linux
def test_block_target_values():
    target_name = "test_memcpy.c"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    res = pp.source_metadata[test_filename]
    assert 0 == 0


# TODO
# test last byte in file touch.

@only_linux
def test_source_fopen():
    target_name = "test_fopen.c"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    fopen_processed_sets = pp.processed_taint_sets
    assert 0 in fopen_processed_sets["main"]["input_bytes"][test_filename]


@only_linux
def test_source_ifstream():
    target_name = "test_ifstream.cpp"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    ifstream_processed_sets = pp.processed_taint_sets
    assert 0 in ifstream_processed_sets["main"]["input_bytes"][test_filename]


@only_linux
def test_cxx_object_propagation():
    target_name = "test_object_propagation.cpp"
    pp = validate_execute_target(target_name)
    object_processed_sets = pp.processed_taint_sets
    fnames = [func for func in object_processed_sets.keys() if "tainted_string" in func]
    assert len(fnames) > 0


# TODO Compute DFG and query if we touch vector in libcxx from object
@only_linux
def test_cxx_vector():
    target_name = "test_vector.cpp"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    vector_processed_sets = pp.processed_taint_sets
    assert 0 in vector_processed_sets["main"]["input_bytes"][test_filename]
