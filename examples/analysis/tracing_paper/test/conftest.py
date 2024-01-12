import pytest


def pytest_addoption(parser):
    """Run the tests with `pytest -s <testname.py> --tdag path/to/tdag`"""
    parser.addoption("--tdag", action="store", default="../ubet/output/Release.tdag")
    parser.addoption("--tdag2", action="store", default="../ubet/output/Debug.tdag")
    parser.addoption(
        "--json", action="store", default="../ubet/output/release_fid.json"
    )
    parser.addoption("--json2", action="store", default="../ubet/output/debug_fid.json")


def pytest_generate_tests(metafunc):
    # This is called for every test. Only get/set command line arguments
    # if the argument is specified in the list of test "fixturenames".
    tdag = metafunc.config.option.tdag
    if "tdag" in metafunc.fixturenames and tdag is not None:
        metafunc.parametrize("tdag", [tdag])

    tdag2 = metafunc.config.option.tdag2
    if "tdag2" in metafunc.fixturenames and tdag2 is not None:
        metafunc.parametrize("tdag2", [tdag2])

    json = metafunc.config.option.json
    if "json" in metafunc.fixturenames and json is not None:
        metafunc.parametrize("json", [json])

    json2 = metafunc.config.option.json2
    if "json2" in metafunc.fixturenames and json2 is not None:
        metafunc.parametrize("json2", [json2])
