from polyprocess import PolyProcess
import pytest
import networkx as nx
import os
import json
import subprocess

cwd = os.getcwd()
test_dir = cwd + "/tests/"
bin_dir = test_dir + "/bin/"

"""
Pytest fixture to init testing env (building tests) 

This runs before any test is executed
"""


@pytest.fixture(scope="session", autouse=True)
def setup_targets():
    # Check if bin dir exists
    if os.path.exists(cwd + "/tests/bin"):
        os.system("rm -r " + cwd + "/tests/bin")
    os.system("mkdir " + cwd + "/tests/bin")
    target_files = [f for f in os.listdir(cwd + "/tests") if f.endswith(".c") or f.endswith(".cpp")]
    for file in target_files:
        assert compile_target(file) == 0


def compile_target(target_name: str) -> int:
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


def test_mmap():
    target_name = "test_mmap.cpp"
    # Find and run test
    target_bin_path = bin_dir + target_name + ".bin"
    print(target_bin_path)
    assert os.path.exists(target_bin_path) is True
    test_filename = test_dir + "/test_data/polytracker_process_set.json"
    os.system("POLYPATH=" + test_filename + " ./" + target_bin_path)
    # Assert that the appropriate files were created
    assert os.path.exists("./polytracker_process_sets.json") is True
    assert os.path.exists("./polytracker_forest.bin") is True
    pp = PolyProcess("./polytracker_process_sets.json", "./polytracker_forest.bin")
    pp.process_taint_sets()
    mmap_processed_sets = pp.processed_taint_sets
    print(mmap_processed_sets)
    # Confirm that main touched tainted byte 0
    assert 0 in mmap_processed_sets["main"]["input_bytes"][test_filename]
    return -1
