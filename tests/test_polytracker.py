import pytest
import os
from polyprocess import PolyProcess

cwd = os.getcwd()
test_dir = cwd + "/tests/"
bin_dir = test_dir + "/bin/"
test_results_dir = bin_dir + "/test_results/"
bitcode_dir = test_dir + "/bitcode/"

"""
Pytest fixture to init testing env (building tests) 

This runs before any test is executed
"""


@pytest.fixture(scope="session", autouse=True)
def setup_targets():
    # Check if bin dir exists
    if os.path.exists(bin_dir):
        os.system("rm -r " + bin_dir)
    os.system("mkdir -p " + test_results_dir)
    if os.path.exists(bitcode_dir):
        os.system("rm -r " + bitcode_dir)
    os.system("mkdir " + bitcode_dir)
    target_files = [f for f in os.listdir(test_dir) if f.endswith(".c") or f.endswith(".cpp")]
    for file in target_files:
        assert polyclang_compile_target(file) == 0


def polyclang_compile_target(target_name: str) -> int:
    is_cxx: bool = False
    if target_name.endswith(".cpp"):
        is_cxx = True
    if is_cxx:
        cxx = os.getenv("CXX")
        ret_val = os.system(
            cxx + " --target-instrument -g -o " + bin_dir + target_name + ".bin " + test_dir + target_name)
    else:
        cc = os.getenv("CC")
        ret_val = os.system(
            cc + " --target-instrument -g -o " + bin_dir + target_name + ".bin " + test_dir + target_name)
    return ret_val


# TODO Parameterize test files?

# Returns the Polyprocess object
def validate_execute_target(target_name):
    target_bin_path = bin_dir + target_name + ".bin"
    assert os.path.exists(target_bin_path) is True
    test_filename = "/polytracker/tests/test_data/test_data.txt"
    os.environ["POLYPATH"] = test_filename
    os.environ["POLYOUTPUT"] = test_results_dir + target_name
    ret_val = os.system(target_bin_path + " " + test_filename)
    assert ret_val == 0
    # Assert that the appropriate files were created
    forest_path = test_results_dir + "/" + target_name + "_forest.bin"
    json_path = test_results_dir + "/" + target_name + "_process_set.json"
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
