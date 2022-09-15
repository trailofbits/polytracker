from os import getenv
import pytest
from shutil import copyfile
from subprocess import CalledProcessError
from tempfile import NamedTemporaryFile

from polytracker import PolyTrackerTrace, ProgramTrace

from .data import *


def _get_instrumented_bin_path(target_name: str) -> Path:
    return BUILD_DIR / f"{target_name}.instrumented"


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
    bin_path = BUILD_DIR / f"{target_name}.bin"
    inst_bin_path = _get_instrumented_bin_path(target_name)
    if bin_path.exists() and not is_out_of_date(bin_path, source_path):
        # we `rm -rf`'d the whole bin directory in setup_targets,
        # so if the binary is already here, it means we built it already this run
        return 0

    build_cmd = ["polytracker", "build"]

    if target_name.endswith(".cpp"):
        build_cmd.append("clang++")
    else:
        build_cmd.append("clang")

    build_cmd += ["-g", "-o", to_native_path(bin_path), to_native_path(source_path)]

    ret = run_natively(*build_cmd)
    if ret:
        return ret

    instrument_cmd = ["polytracker", "instrument-targets", bin_path.name]

    ret = run_natively(*instrument_cmd)
    if ret:
        return ret

    move_command = [
        "mv",
        inst_bin_path.name,
        to_native_path(inst_bin_path),
    ]

    run_natively(*move_command)

    return ret


# Returns the Polyprocess object
def validate_execute_target(
    target_name: str,
    config_path: Optional[Union[str, Path]],
    input_bytes: Optional[bytes] = None,
    return_exceptions: bool = False,
    taint_all: bool = False,
) -> Union[ProgramTrace, CalledProcessError]:
    target_bin_path = _get_instrumented_bin_path(target_name)
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
        "POLYFUNC": "1",
        "POLYTRACKER_STDOUT_SINK": getenv("POLYTRACKER_STDOUT_SINK", "0"),
        "POLYTRACKER_STDERR_SINK": getenv("POLYTRACKER_STDERR_SINK", "0"),
        "POLYTRACKER_TAINT_ARGV": getenv("POLYTRACKER_TAINT_ARGV", "0"),
    }
    if taint_all:
        del env["POLYPATH"]
    tmp_config = Path(__file__).parent.parent / ".polytracker_config.json"
    if config_path is not None:
        copyfile(str(CONFIG_DIR / "new_range.json"), str(tmp_config))
    try:
        ret_val = run_natively(env=env, *[to_native_path(target_bin_path), input_path])
    finally:
        if tmp_config.exists():
            tmp_config.unlink()  # we can't use `missing_ok=True` here because that's only available in Python 3.9
        if tmp_input_file is not None:
            path = Path(tmp_input_file.name)
            if path.exists():
                path.unlink()
    if ret_val != 0:
        error = CalledProcessError(
            ret_val, f"`{target_bin_path} {' '.join(input_path)}`"
        )
        if return_exceptions:
            return error
        else:
            raise error
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
    if "taint_all" in marker.kwargs and marker.kwargs["taint_all"] is True:
        taint_all = True
    else:
        taint_all = False

    return_exceptions = (
        "return_exceptions" in marker.kwargs and marker.kwargs["return_exceptions"]
    )

    assert polyclang_compile_target(target_name) == 0

    return validate_execute_target(
        target_name,
        config_path=config_path,
        input_bytes=input_bytes,
        return_exceptions=return_exceptions,
        taint_all=taint_all,
    )
