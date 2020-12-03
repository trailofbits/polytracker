import json
import platform
import subprocess
import sys
from functools import wraps
from pathlib import Path
from typing import Any, Dict, Optional


from polytracker.containerization import DockerContainer


IS_LINUX: bool = platform.system() == "Linux"
IS_NATIVE: bool = IS_LINUX and subprocess.call(["/usr/bin/env", "sh", "which", "polybuild"]) == 0


_DOCKER: Optional[DockerContainer] = None


def requires_native(func):
    global IS_NATIVE
    if IS_NATIVE:
        return func
    else:

        @wraps(func)
        def run_in_docker(*args, **kwargs):
            sys.stderr.write(f"Running {func!r} in Docker because it requires a native install of PolyTracker...\n")
            global _DOCKER
            if _DOCKER is None:
                _DOCKER = DockerContainer()
            assert _DOCKER.run("/usr/bin/env", "pytest", "-k", func.__name__, interactive=False,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0

        return run_in_docker


def generate_bad_path() -> Path:
    path = Path("BADPATH")
    while path.exists():
        path = path.with_name(f"_{path.name}_")
    return path


TEST_DATA_DIR: Path = Path(__file__).parent / "test_data"
BAD_PATH: Path = generate_bad_path()
BAD_FOREST_PATH: Path = TEST_DATA_DIR / "bad_forest.bin"
GOOD_FOREST_PATH: Path = TEST_DATA_DIR / "polytracker_forest.bin"
PROCESS_SET_PATH: Path = TEST_DATA_DIR / "polytracker_process_set.json"
TEST_DATA_PATH: Path = TEST_DATA_DIR / "test_data.txt"
BIN_DIR: Path = TEST_DATA_DIR / "bin"
TEST_RESULTS_DIR = BIN_DIR / "test_results"
BITCODE_DIR = TEST_DATA_DIR / "bitcode"


__PROCESS_SET: Optional[Dict[str, Any]] = None


def process_set() -> Dict[str, Any]:
    global __PROCESS_SET
    if __PROCESS_SET is None:
        with open(PROCESS_SET_PATH, "r") as f:
            __PROCESS_SET = json.load(f)
    return __PROCESS_SET


def canonical_mapping() -> Dict[int, int]:
    pset: Dict[str, Any] = process_set()
    if "canonical_mapping" not in pset:
        raise ValueError(
            f'Expected to find a "canonical_mapping" key in {PROCESS_SET_PATH!s}. ' "Perhaps it is using a newer JSON schema?"
        )
    elif len(pset["canonical_mapping"]) != 1:
        raise ValueError(f"{PROCESS_SET_PATH!s} was expected to have only one source, but found {pset.keys()!r}")
    return dict(next(iter(pset["canonical_mapping"].values())))
