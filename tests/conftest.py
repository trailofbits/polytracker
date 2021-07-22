import pytest
from shutil import rmtree

from .data import *


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "program_trace: mark the C/C++ source file to be automatically compiled, instrumented, and run for the test",
    )


@pytest.fixture(scope="session", autouse=True)
def setup_targets():
    """
    Pytest fixture to init testing env (building tests)

    This runs before any test is executed

    """
    if BUILD_DIR.exists():
        rmtree(BUILD_DIR)
    BUILD_DIR.mkdir()
    if TEST_RESULTS_DIR.exists():
        rmtree(TEST_RESULTS_DIR)
    TEST_RESULTS_DIR.mkdir()


pytest_plugins = [
    "tests.tracing",
]
