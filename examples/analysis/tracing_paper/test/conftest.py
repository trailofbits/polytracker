import pytest


def pytest_addoption(parser):
    """Run the tests with `pytest -s <testname.py> --tdag path/to/tdag`"""
    parser.addoption(
        "--tdag", action="store", default="../ubet/output/U_2001E.NTF/Release.tdag"
    )


def pytest_generate_tests(metafunc):
    # This is called for every test. Only get/set command line arguments
    # if the argument is specified in the list of test "fixturenames".
    option_value = metafunc.config.option.tdag
    if "tdag" in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("tdag", [option_value])
