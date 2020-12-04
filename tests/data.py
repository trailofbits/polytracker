import json
import os
import platform
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional


from polytracker.containerization import DockerContainer


IS_LINUX: bool = platform.system() == "Linux"
CAN_RUN_NATIVELY: bool = IS_LINUX and os.getenv("POLYTRACKER_CAN_RUN_NATIVELY", "0") != "0" and \
                         os.getenv("POLYTRACKER_CAN_RUN_NATIVELY", "") != ""


_DOCKER: Optional[DockerContainer] = None


def to_native_path(host_path: Path) -> str:
    if CAN_RUN_NATIVELY:
        return str(host_path)
    return str(Path("/workdir") / host_path.relative_to(Path(__file__).parent.parent))


def run_natively(*args, **kwargs) -> int:
    if CAN_RUN_NATIVELY:
        return subprocess.call(*args, **kwargs)
    else:
        sys.stderr.write(f"Running `{' '.join(args)}` in Docker because it requires a native install of PolyTracker...\n")
        global _DOCKER
        if _DOCKER is None:
            _DOCKER = DockerContainer()
        return _DOCKER.run(  # type: ignore
            *args, **kwargs, interactive=False, stdout=sys.stdout, stderr=sys.stderr, cwd=str(Path(__file__).parent.parent)
        ).returncode


def generate_bad_path() -> Path:
    path = Path("BADPATH")
    while path.exists():
        path = path.with_name(f"_{path.name}_")
    return path


TESTS_DIR: Path = Path(__file__).parent
TEST_DATA_DIR: Path = TESTS_DIR / "test_data"
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
