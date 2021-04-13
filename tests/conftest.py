import pytest


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "program_trace: mark the C/C++ source file to be automatically compiled, instrumented, and instrumented for the test",
    )


def pytest_addoption(parser):
    parser.addoption("--json", action="store", default=None, help="Path to JSON file")
    parser.addoption(
        "--forest", action="store", default=None, help="Path to forest file"
    )


@pytest.fixture
def json_path(pytestconfig):
    return pytestconfig.getoption("--json")


@pytest.fixture
def forest_path(pytestconfig):
    return pytestconfig.getoption("--forest")
