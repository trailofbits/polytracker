import pytest
import os
from polyprocess import PolyProcess
import subprocess


TEST_DIR = os.path.realpath(os.path.dirname(__file__))
BIN_DIR = os.path.join(TEST_DIR, "bin")
TEST_RESULTS_DIR = os.path.join(BIN_DIR, "test_results")
BITCODE_DIR = os.path.join(TEST_DIR, "bitcode")

"""
Pytest fixture to init testing env (building tests) 

This runs before any test is executed
"""


@pytest.fixture(scope="session", autouse=True)
def setup_targets():
    # Check if bin dir exists
    if os.path.exists(BIN_DIR):
        subprocess.call(["rm", "-r", BIN_DIR])
    subprocess.call(["mkdir", "-p", BIN_DIR])
    if os.path.exists(TEST_RESULTS_DIR):
        subprocess.call(["rm", "-r", TEST_RESULTS_DIR])
    subprocess.call(["mkdir", "-p", TEST_RESULTS_DIR])
    if os.path.exists(BITCODE_DIR):
        subprocess.call(["rm", "-r", BITCODE_DIR])
    subprocess.call(["mkdir", BITCODE_DIR])
    target_files = [f for f in os.listdir(TEST_DIR) if f.endswith(".c") or f.endswith(".cpp")]
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
            os.path.join(BIN_DIR, target_name) + ".bin",
            os.path.join(TEST_DIR, target_name),
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
            os.path.join(BIN_DIR, target_name) + ".bin",
            os.path.join(TEST_DIR, target_name),
        ]
        ret_val = subprocess.call(compile_command)
    return ret_val


# TODO Parameterize test files?

# Returns the Polyprocess object
def validate_execute_target(target_name):
    target_bin_path = os.path.join(BIN_DIR, target_name + ".bin")
    assert os.path.exists(target_bin_path) is True
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    os.environ["POLYPATH"] = test_filename
    os.environ["POLYOUTPUT"] = os.path.join(TEST_RESULTS_DIR, target_name)
    ret_val = subprocess.call([target_bin_path, test_filename])
    assert ret_val == 0
    # Assert that the appropriate files were created
    forest_path = os.path.join(TEST_RESULTS_DIR, target_name + "_forest.bin")
    json_path = os.path.join(TEST_RESULTS_DIR, target_name + "_process_set.json")
    assert os.path.exists(forest_path) is True
    assert os.path.exists(json_path) is True
    pp = PolyProcess(json_path, forest_path)
    pp.process_taint_sets()
    return pp


def test_source_mmap():
    target_name = "test_mmap.c"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    # Find and run test
    pp = validate_execute_target(target_name)
    mmap_processed_sets = pp.processed_taint_sets
    # Confirm that main touched tainted byte 0
    assert 0 in mmap_processed_sets["main"]["input_bytes"][test_filename]


def test_source_open():
    target_name = "test_open.c"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    open_processed_sets = pp.processed_taint_sets
    assert 0 in open_processed_sets["main"]["input_bytes"][test_filename]


def test_source_fopen():
    target_name = "test_fopen.c"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    fopen_processed_sets = pp.processed_taint_sets
    assert 0 in fopen_processed_sets["main"]["input_bytes"][test_filename]


def test_source_ifstream():
    target_name = "test_ifstream.cpp"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    ifstream_processed_sets = pp.processed_taint_sets
    assert 0 in ifstream_processed_sets["main"]["input_bytes"][test_filename]


def test_cxx_object_propagation():
    target_name = "test_object_propagation.cpp"
    pp = validate_execute_target(target_name)
    object_processed_sets = pp.processed_taint_sets
    fnames = [func for func in object_processed_sets.keys() if "tainted_string" in func]
    assert len(fnames) > 0


# TODO Compute DFG and query if we touch vector in libcxx from object
def test_cxx_vector():
    target_name = "test_vector.cpp"
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    pp = validate_execute_target(target_name)
    vector_processed_sets = pp.processed_taint_sets
    assert 0 in vector_processed_sets["main"]["input_bytes"][test_filename]
