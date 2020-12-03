import os
import pytest
import shutil

from polytracker import parse, ProgramTrace

from .data import *


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
    target_files = [f for f in os.listdir(TESTS_DIR) if f.endswith(".c") or f.endswith(".cpp")]
    for file in target_files:
        assert polyclang_compile_target(file) == 0


def polyclang_compile_target(target_name: str) -> int:
    is_cxx: bool = False
    if target_name.endswith(".cpp"):
        is_cxx = True
    if is_cxx:
        compile_command = [
            "/usr/bin/env",
            "polybuild++",
            "--instrument-target",
            "-g",
            "-o",
            to_native_path(BIN_DIR / f"{target_name}.bin"),
            to_native_path(TESTS_DIR / target_name),
        ]
        ret_val = run_natively(*compile_command)
    else:
        compile_command = [
            "/usr/bin/env",
            "polybuild",
            "--instrument-target",
            "-g",
            "-o",
            to_native_path(BIN_DIR / f"{target_name}.bin"),
            to_native_path(TESTS_DIR / target_name),
        ]
        ret_val = run_natively(*compile_command)
    return ret_val


# Returns the Polyprocess object
def validate_execute_target(target_name: str) -> ProgramTrace:
    target_bin_path = BIN_DIR / f"{target_name}.bin"
    if IS_NATIVE:
        assert target_bin_path.exists()
    ret_val = run_natively(
        *[to_native_path(target_bin_path), to_native_path(TEST_DATA_PATH)],
        env={"POLYPATH": to_native_path(TEST_DATA_PATH), "POLYOUTPUT": to_native_path(TEST_RESULTS_DIR / target_name)},
    )
    assert ret_val == 0
    # Assert that the appropriate files were created
    forest_path = TEST_RESULTS_DIR / f"{target_name}0_forest.bin"
    # Add the 0 here for thread counting.
    json_path = TEST_RESULTS_DIR / f"{target_name}0_process_set.json"
    assert forest_path.exists()
    assert json_path.exists()
    with open(json_path, "r") as f:
        json_obj = json.load(f)
    return parse(json_obj, str(forest_path))


def test_source_mmap():
    target_name = "test_mmap.c"
    # Find and run test
    pp = validate_execute_target(target_name)
    assert 0 in pp.functions["main"].input_bytes[str(TEST_DATA_PATH)]


def test_source_open():
    target_name = "test_open.c"
    pp = validate_execute_target(target_name)
    assert 0 in pp.functions["main"].input_bytes[str(TEST_DATA_PATH)]


# TODO: Update this test
# def test_polyprocess_taint_sets(json_path, forest_path):
#     logger.info("Testing taint set processing")
#     poly_proc = PolyProcess(json_path, forest_path)
#     poly_proc.process_taint_sets()
#     poly_proc.set_output_filepath("/tmp/polytracker.json")
#     poly_proc.output_processed_json()
#     assert os.path.exists("/tmp/polytracker.json") is True
#     with open("/tmp/polytracker.json", "r") as poly_json:
#         json_size = os.path.getsize("/tmp/polytracker.json")
#         polytracker_json = json.loads(poly_json.read(json_size))
#         if "tainted_functions" in poly_proc.polytracker_json:
#             assert "tainted_functions" in polytracker_json
#             for func in poly_proc.polytracker_json["tainted_functions"]:
#                 if "cmp_bytes" in poly_proc.polytracker_json["tainted_functions"][func]:
#                     assert "cmp_bytes" in polytracker_json["tainted_functions"][func]
#                 if "input_bytes" in poly_proc.polytracker_json["tainted_functions"][func]:
#                     assert "input_bytes" in polytracker_json["tainted_functions"][func]
#         assert "version" in polytracker_json
#         assert polytracker_json["version"] == poly_proc.polytracker_json["version"]
#         assert "runtime_cfg" in polytracker_json
#         assert len(polytracker_json["runtime_cfg"]["main"]) == 1
#         assert "taint_sources" in polytracker_json
#         assert "canonical_mapping" not in polytracker_json
#         assert "tainted_input_blocks" in polytracker_json


def test_source_open_full_validate_schema():
    target_name = "test_open.c"
    pp = validate_execute_target(target_name)
    forest_path = os.path.join(TEST_RESULTS_DIR, target_name + "0_forest.bin")
    json_path = os.path.join(TEST_RESULTS_DIR, target_name + "0_process_set.json")
    assert 0 in pp.functions["main"].input_bytes[str(TEST_DATA_PATH)]
    # TODO: Uncomment once we update this function
    # test_polyprocess_taint_sets(json_path, forest_path)


def test_memcpy_propagate():
    target_name = "test_memcpy.c"
    pp = validate_execute_target(target_name)
    assert 1 in pp.functions["dfs$touch_copied_byte"].input_bytes[str(TEST_DATA_PATH)]


def test_taint_log():
    target_name = "test_taint_log.c"
    pp = validate_execute_target(target_name)
    input_bytes = pp.functions["main"].input_bytes[str(TEST_DATA_PATH)]
    for i in range(0, 10):
        assert i in input_bytes


# This is a bad name for this test
# This test compares the taint sources info with the tainted block info
# When reading an entire file in a single block
# Basically make sure the start/end match to prevent off-by-one errors
# TODO
def test_block_target_values():
    target_name = "test_memcpy.c"
    _ = validate_execute_target(target_name)


# TODO
# test last byte in file touch.


def test_source_fopen():
    target_name = "test_fopen.c"
    pp = validate_execute_target(target_name)
    assert 0 in pp.functions["main"].input_bytes[str(TEST_DATA_PATH)]


def test_source_ifstream():
    target_name = "test_ifstream.cpp"
    pp = validate_execute_target(target_name)
    assert 0 in pp.functions["main"].input_bytes[str(TEST_DATA_PATH)]


def test_cxx_object_propagation():
    target_name = "test_object_propagation.cpp"
    pp = validate_execute_target(target_name)
    # object_processed_sets = pp.processed_taint_sets
    # TODO: Update "tainted_string" in the ProgramTrace class
    # fnames = [func for func in object_processed_sets.keys() if "tainted_string" in func]
    # assert len(fnames) > 0


# TODO Compute DFG and query if we touch vector in libcxx from object
def test_cxx_vector():
    target_name = "test_vector.cpp"
    pp = validate_execute_target(target_name)
    assert 0 in pp.functions["main"].input_bytes[str(TEST_DATA_PATH)]
