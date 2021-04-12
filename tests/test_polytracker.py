from collections import defaultdict
import os
import pytest
from shutil import copyfile

from polytracker import (
    BasicBlockEntry,
    FunctionEntry,
    FunctionReturn,
    PolyTrackerTrace,
    ProgramTrace,
)

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
    target_name: str, config_path: Optional[Union[str, Path]], input_bytes: Optional[bytes] = None
) -> ProgramTrace:
    target_bin_path = BIN_DIR / f"{target_name}.bin"
    if CAN_RUN_NATIVELY:
        assert target_bin_path.exists()
    db_path = TEST_RESULTS_DIR / f"{target_name}.db"
    if db_path.exists():
        db_path.unlink()
    if input_bytes is None:
        input_path = to_native_path(TEST_DATA_PATH)
        tmp_input_file = None
    else:
        tmp_input_file = NamedTemporaryFile(dir=str(TEST_DATA_DIR), delete=False)
        tmp_input_file.write(input_bytes)
        input_path = to_native_path(tmp_input_file.name)
        tmp_input_file.close()
    env = {
        "POLYPATH": input_path,
        "POLYDB": to_native_path(db_path),
        "POLYTRACE": "1",
        "POLYFUNC": "1"
    }
    tmp_config = Path(__file__).parent.parent / ".polytracker_config.json"
    if config_path is not None:
        copyfile(str(CONFIG_DIR / "new_range.json"), str(tmp_config))
    try:
        ret_val = run_natively(
            env=env, *[to_native_path(target_bin_path), input_path]
        )
    finally:
        if tmp_config.exists():
            tmp_config.unlink()  # we can't use `missing_ok=True` here because that's only available in Python 3.9
        if tmp_input_file is not None:
            path = Path(tmp_input_file.name)
            if path.exists():
                path.unlink()
    assert ret_val == 0
    # Assert that the appropriate files were created
    return PolyTrackerTrace.load(db_path)


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
    if "input" in marker.kwargs:
        input_val = marker.kwargs["input"]
        if isinstance(input_val, str):
            input_bytes: Optional[bytes] = input_val.encode("utf-8")
        elif isinstance(input_val, bytes):
            input_bytes = input_val
        else:
            raise ValueError(f"Invalid input argument: {input_val!r}")
    else:
        input_bytes = None

    assert polyclang_compile_target(target_name) == 0

    return validate_execute_target(target_name, config_path=config_path, input_bytes=input_bytes)


@pytest.mark.program_trace("test_mmap.c")
def test_source_mmap(program_trace: ProgramTrace):
    assert any(
        byte_offset.offset == 0
        for byte_offset in program_trace.get_function("main").taints()
    )


@pytest.mark.program_trace("test_open.c")
def test_source_open(program_trace: ProgramTrace):
    assert any(
        byte_offset.offset == 0
        for byte_offset in program_trace.get_function("main").taints()
    )


@pytest.mark.program_trace("test_control_flow.c")
def test_control_flow(program_trace: ProgramTrace):
    # make sure the trace contains all of the functions:
    main = program_trace.get_function("main")
    assert len(main.called_from()) == 0
    assert len(main.calls_to()) == 1
    func1 = program_trace.get_function("func1")
    assert func1 in main.calls_to()
    assert len(func1.called_from()) == 1
    assert main in func1.called_from()
    assert len(func1.calls_to()) == 1
    func2 = program_trace.get_function("func2")
    assert func2 in func1.calls_to()
    assert len(func2.called_from()) == 2
    assert func1 in func2.called_from()
    assert func2 in func2.called_from()
    assert len(func2.calls_to()) == 1
    entries: Dict[str, int] = defaultdict(int)
    returns: Dict[str, int] = defaultdict(int)
    for event in program_trace:
        if isinstance(event, BasicBlockEntry):
            assert event.entry_count() == 0
        elif isinstance(event, FunctionEntry):
            entries[event.function.name] += 1
        elif isinstance(event, FunctionReturn):
            returns[event.function.name] += 1
    assert entries["main"] == 1
    assert entries["func1"] == 1
    assert entries["func2"] == 6
    assert returns["func1"] == 1
    assert returns["func2"] == 6
    # our instrumentation doesn't currently emit a function return event for main, but that might change in the future
    # so for now just ignore main


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
def test_source_open_full_validate_schema(program_trace: ProgramTrace):
    forest_path = os.path.join(TEST_RESULTS_DIR, "test_open.c0_forest.bin")
    json_path = os.path.join(TEST_RESULTS_DIR, "test_open.c0_process_set.json")
    assert any(
        byte_offset.offset == 0
        for byte_offset in program_trace.get_function("main").taints()
    )
    # TODO: Uncomment once we update this function
    # test_polyprocess_taint_sets(json_path, forest_path)


@pytest.mark.program_trace("test_memcpy.c")
def test_memcpy_propagate(program_trace: ProgramTrace):
    func = program_trace.get_function("touch_copied_byte")
    taints = func.taints()
    assert len(taints) == 1
    assert next(iter(taints)).offset == 0


@pytest.mark.program_trace("test_taint_log.c")
def test_taint_log(program_trace: ProgramTrace):
    taints = program_trace.get_function("main").taints()
    for i in range(0, 10):
        assert any(i == offset.offset for offset in taints)


@pytest.mark.program_trace(
    "test_taint_log.c", config_path=CONFIG_DIR / "new_range.json"
)
def test_config_files(program_trace: ProgramTrace):
    # the new_range.json config changes the polystart/polyend to
    # POLYSTART: 1, POLYEND: 3
    taints = program_trace.get_function("main").taints()
    for i in range(1, 4):
        assert any(i == offset.offset for offset in taints)
    for i in range(4, 10):
        assert all(i != offset.offset for offset in taints)


@pytest.mark.program_trace("test_fopen.c")
def test_source_fopen(program_trace: ProgramTrace):
    taints = program_trace.get_function("main").taints()
    assert any(offset.offset == 0 for offset in taints)


@pytest.mark.program_trace("test_ifstream.cpp")
def test_source_ifstream(program_trace: ProgramTrace):
    taints = program_trace.get_function("main").taints()
    assert any(offset.offset == 0 for offset in taints)


@pytest.mark.program_trace("test_object_propagation.cpp")
def test_cxx_object_propagation(program_trace: ProgramTrace):
    for func in program_trace.functions:
        if func.demangled_name.startswith("tainted_string("):
            assert len(func.taints()) > 0


# TODO Compute DFG and query if we touch vector in libcxx from object
@pytest.mark.program_trace("test_vector.cpp")
def test_cxx_vector(program_trace: ProgramTrace):
    assert any(
        byte_offset.offset == 0
        for byte_offset in program_trace.get_function("main").taints()
    )


@pytest.mark.program_trace("test_fgetc.c", input="ABCDEFGH")
def test_fgetc(program_trace: ProgramTrace):
    for event in program_trace:
        print(event)
