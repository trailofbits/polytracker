import subprocess
import sys
from pathlib import Path
from typing import Optional, Union


from polytracker.containerization import CAN_RUN_NATIVELY, DockerContainer


_DOCKER: Optional[DockerContainer] = None


def to_native_path(host_path: Union[str, Path]) -> str:
    if CAN_RUN_NATIVELY:
        return str(host_path)
    if not isinstance(host_path, Path):
        host_path = Path(host_path)
    return str(Path("/workdir") / host_path.relative_to(Path(__file__).parent.parent))


def docker_container() -> DockerContainer:
    global _DOCKER
    if _DOCKER is None:
        _DOCKER = DockerContainer()
    return _DOCKER


def run_natively(*args, **kwargs) -> int:
    if CAN_RUN_NATIVELY:
        return subprocess.call(args, **kwargs)
    else:
        if "env" in kwargs:
            env = kwargs["env"]
            del kwargs["env"]
        else:
            env = {}
        sys.stderr.write(f"Running `{' '.join(args)}` in Docker because it requires a native install of PolyTracker...\n")
        if "POLYDB" in env:
            # write to a different path inside the container to speed things up on macOS:
            old_polydb_path = env["POLYDB"]
            env["POLYDB"] = "/polytracker.db"
            args = tuple(
                [
                    "bash",
                    "-c",
                    " ".join(
                        args + (";", "exitcode=$?", ";", "mv", "/polytracker.db", old_polydb_path, ";", "exit", "$exitcode")
                    ),
                ]
            )
        return docker_container().run(  # type: ignore
            *args,
            **kwargs,
            interactive=False,
            stdout=sys.stdout,
            stderr=sys.stderr,
            cwd=str(Path(__file__).parent.parent),
            env=env,
        )


def generate_bad_path() -> Path:
    path = Path("BADPATH")
    while path.exists():
        path = path.with_name(f"_{path.name}_")
    return path


TESTS_DIR: Path = Path(__file__).parent
TEST_DATA_DIR: Path = TESTS_DIR / "test_data"
BAD_PATH: Path = generate_bad_path()
CONFIG_DIR: Path = TESTS_DIR / "configs"
TEST_DATA_PATH: Path = TEST_DATA_DIR / "test_data.txt"
BUILD_DIR: Path = TEST_DATA_DIR / "build"
TEST_RESULTS_DIR = TEST_DATA_DIR / "test_results"
