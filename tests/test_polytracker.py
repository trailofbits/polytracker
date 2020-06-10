import pytest
import os

cwd = os.getcwd()
test_dir = cwd + "/tests/"
bin_dir = test_dir + "/bin/"
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
    os.system("mkdir " + bin_dir)
    if os.path.exists(bitcode_dir):
        os.system("rm -r " + bitcode_dir)
    os.system("mkdir " + bitcode_dir)
    target_files = [f for f in os.listdir(test_dir) if f.endswith(".c") or f.endswith(".cpp")]
    for file in target_files:
        assert polyclang_compile_target(file) == 0
        assert extract_bitcode(file) == 0
        assert instrument_bitcode(file) == 0
        assert recompile_target(file) == 0


def polyclang_compile_target(target_name: str) -> int:
    is_cxx: bool = False
    if target_name.endswith(".cpp"):
        is_cxx = True
    if is_cxx:
        cxx = os.getenv("CXX")
        ret_val = os.system(cxx + " -g -o " + bin_dir + target_name + ".bin " + test_dir + target_name)
    else:
        cc = os.getenv("CC")
        ret_val = os.system(cc + " -g -o " + bin_dir + target_name + ".bin " + test_dir + target_name)
    return ret_val


# TODO Thoguhts are to extract bitcode, then add a new feature to polyclang --instrument bitcode
# TODO then this does not trigger the gllvm, but instead triggers opt to do its thang
def extract_bitcode(target_name: str) -> int:
    ret_val = os.system("get-bc -b " + bin_dir + target_name + ".bin")
    assert ret_val == 0
    ret_val = os.system("mv " + bin_dir + target_name + ".bin.bc " + bitcode_dir)
    assert os.path.exists(bitcode_dir + target_name + ".bin.bc") is True
    return ret_val


def instrument_bitcode(target_name: str) -> int:
    return 0


def recompile_target(target_name: str) -> int:
    return 0


# TODO Make function to test functionality for all sources

# TODO Make test that touches no taint, and then confirm lack of things

# TODO Parameterize test files?

def test_source_mmap():
    target_name = "test_mmap.c"
    # Find and run test
    target_bin_path = bin_dir + target_name + ".bin"
    print(target_bin_path)
    assert os.path.exists(target_bin_path) is True
    test_filename = "/polytracker/tests/test_data/polytracker_process_set.json"
    os.environ["POLYPATH"] = test_filename
    ret_val = os.system(target_bin_path + " " + test_filename)
    assert ret_val == 0
    # Assert that the appropriate files were created
    # assert os.path.exists("./polytracker_process_sets.json") is True
    # assert os.path.exists("./polytracker_forest.bin") is True
    # pp = PolyProcess("./polytracker_process_sets.json", "./polytracker_forest.bin")
    # pp.process_taint_sets()
    # mmap_processed_sets = pp.processed_taint_sets
    # TODO Check for tainted input chunks
    # TODO check for tainted bytes
    # print(mmap_processed_sets)
    # Confirm that main touched tainted byte 0
    # assert 0 in mmap_processed_sets["main"]["input_bytes"][test_filename]
    # return -1
