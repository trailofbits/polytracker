import pytest
from shutil import copyfile

from polytracker import TaintForestFunctionInfo
from polytracker.tracing import PolyTrackerTrace
from polytracker.database import DBPolyTrackerTrace

from .data import *

"""
Pytest fixture to init testing env (building tests) 

This runs before any test is executed
"""


@pytest.fixture(scope="session", autouse=True)
def setup_targets():
    if not BIN_DIR.exists():
        BIN_DIR.mkdir()
    if not TEST_RESULTS_DIR.exists():
        TEST_RESULTS_DIR.mkdir()
    if not BITCODE_DIR.exists():
        BITCODE_DIR.mkdir()


def is_out_of_date(path: Path, *also_compare_to: Path) -> bool:
    if not path.exists():
        return True
    elif CAN_RUN_NATIVELY:
        return (
            True  # For now, always rebuild binaries if we can run PolyTracker natively
        )
    # We need to run PolyTracker in a Docker container.
    last_build_time = docker_container().last_build_time()
    if last_build_time is None:
        # The Docker container hasn't been built yet!
        return True
    last_path_modification = path.stat().st_mtime
    if last_build_time >= last_path_modification:
        # The Docker container was rebuilt since the last time `path` was modified
        return True
    for also_compare in also_compare_to:
        other_time = also_compare.stat().st_mtime
        if other_time >= last_path_modification:
            # this dependency was modified after `path` was modified
            return True
    return False


def polyclang_compile_target(target_name: str) -> int:
    source_path = TESTS_DIR / target_name
    bin_path = BIN_DIR / f"{target_name}.bin"
    if not is_out_of_date(bin_path, source_path):
        # the bin is newer than both our last build of PolyTracker and its source code, so we are good
        return 0
    if target_name.endswith(".cpp"):
        build_cmd: str = "polybuild++"
    else:
        build_cmd = "polybuild"
    compile_command = [
        "/usr/bin/env",
        build_cmd,
        "--instrument-target",
        "-g",
        "-o",
        to_native_path(bin_path),
        to_native_path(source_path),
    ]
    return run_natively(*compile_command)


# Returns the Polyprocess object
def validate_execute_target(
    target_name: str, config_path: Optional[Union[str, Path]]
) -> PolyTrackerTrace:
    target_bin_path = BIN_DIR / f"{target_name}.bin"
    if CAN_RUN_NATIVELY:
        assert target_bin_path.exists()
    db_path = TEST_RESULTS_DIR / f"{target_name}.db"
    env = {
        "POLYPATH": to_native_path(TEST_DATA_PATH),
        "POLYDB": to_native_path(db_path),
        "POLYTRACE": "1",
    }
    tmp_config = Path(__file__).parent.parent / ".polytracker_config.json"
    if config_path is not None:
        copyfile(str(CONFIG_DIR / "new_range.json"), str(tmp_config))
    try:
        ret_val = run_natively(
            *[to_native_path(target_bin_path), to_native_path(TEST_DATA_PATH)], env=env
        )
    finally:
        if tmp_config.exists():
            tmp_config.unlink()  # we can't use `missing_ok=True` here because that's only available in Python 3.9
    assert ret_val == 0
    # Assert that the appropriate files were created
    return DBPolyTrackerTrace.load(db_path)


@pytest.fixture
def program_trace(request):
    marker = request.node.get_closest_marker("program_trace")
    if marker is None:
        raise ValueError(
            """The program_trace fixture must be called with a target file name to compile. For example:

    @pytest.mark.program_trace("foo.c")
    def test_foo(program_trace: ProgramTrace):
        \"\"\"foo.c will be compiled, instrumented, and run, and program_trace will be the resulting ProgramTrace\"\"\"
        ...
"""
        )

    target_name = marker.args[0]
    if "config_path" in marker.kwargs:
        config_path = marker.kwargs["config_path"]
    else:
        config_path = None

    assert polyclang_compile_target(target_name) == 0

    return validate_execute_target(target_name, config_path=config_path)


@pytest.mark.program_trace("test_mmap.c")
def test_source_mmap(program_trace: PolyTrackerTrace):
    assert (
        0 in program_trace.functions["main"].input_bytes[to_native_path(TEST_DATA_PATH)]
    )


@pytest.mark.program_trace("test_open.c")
def test_source_open(program_trace: PolyTrackerTrace):
    assert (
        0 in program_trace.functions["main"].input_bytes[to_native_path(TEST_DATA_PATH)]
    )


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


@pytest.mark.program_trace("test_open.c")
def test_source_open_full_validate_schema(program_trace: PolyTrackerTrace):
    forest_path = os.path.join(TEST_RESULTS_DIR, "test_open.c0_forest.bin")
    json_path = os.path.join(TEST_RESULTS_DIR, "test_open.c0_process_set.json")
    assert (
        0 in program_trace.functions["main"].input_bytes[to_native_path(TEST_DATA_PATH)]
    )
    # TODO: Uncomment once we update this function
    # test_polyprocess_taint_sets(json_path, forest_path)


@pytest.mark.program_trace("test_memcpy.c")
def test_memcpy_propagate(program_trace: PolyTrackerTrace):
    info = program_trace.functions["dfs$touch_copied_byte"]
    assert isinstance(info, TaintForestFunctionInfo)
    assert 1 in info.input_byte_labels[to_native_path(TEST_DATA_PATH)]


@pytest.mark.program_trace("test_taint_log.c")
def test_taint_log(program_trace: PolyTrackerTrace):
    input_bytes = program_trace.functions["main"].input_bytes[
        to_native_path(TEST_DATA_PATH)
    ]
    for i in range(0, 10):
        assert i in input_bytes


@pytest.mark.program_trace(
    "test_taint_log.c", config_path=CONFIG_DIR / "new_range.json"
)
def test_config_files(program_trace: PolyTrackerTrace):
    # the new_range.json config changes the polystart/polyend to
    # POLYSTART: 1, POLYEND: 3
    for i in range(1, 4):
        assert (
            i
            in program_trace.functions["main"].input_bytes[
                to_native_path(TEST_DATA_PATH)
            ]
        )
    for i in range(4, 10):
        assert (
            i
            not in program_trace.functions["main"].input_bytes[
                to_native_path(TEST_DATA_PATH)
            ]
        )


@pytest.mark.program_trace("test_fopen.c")
def test_source_fopen(program_trace: PolyTrackerTrace):
    assert (
        0 in program_trace.functions["main"].input_bytes[to_native_path(TEST_DATA_PATH)]
    )


@pytest.mark.program_trace("test_ifstream.cpp")
def test_source_ifstream(program_trace: PolyTrackerTrace):
    assert (
        0 in program_trace.functions["main"].input_bytes[to_native_path(TEST_DATA_PATH)]
    )


@pytest.mark.program_trace("test_object_propagation.cpp")
def test_cxx_object_propagation(program_trace: PolyTrackerTrace):
    # object_processed_sets = pp.processed_taint_sets
    # TODO: Update "tainted_string" in the ProgramTrace class
    # fnames = [func for func in object_processed_sets.keys() if "tainted_string" in func]
    # assert len(fnames) > 0
    pass


# TODO Compute DFG and query if we touch vector in libcxx from object
@pytest.mark.program_trace("test_vector.cpp")
def test_cxx_vector(program_trace: PolyTrackerTrace):
    assert (
        0 in program_trace.functions["main"].input_bytes[to_native_path(TEST_DATA_PATH)]
    )
