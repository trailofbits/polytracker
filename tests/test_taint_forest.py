import logging
import pytest

from polytracker.taint_forest import TaintForest

from .data import *

logger = logging.getLogger("test_taint_forest:")


def test_taint_forest_creation():
    logger.info("Testing TaintForest object creation")

    with pytest.raises(ValueError, match="Taint forest file does not exist: *"):
        TaintForest(str(BAD_PATH))

    # This implicitly tests to make sure that no error is raised
    TaintForest(str(GOOD_FOREST_PATH))


def test_taint_forest_validation():
    with pytest.raises(ValueError, match="Taint forest is not a multiple of 8 bytes!"):
        TaintForest(str(BAD_FOREST_PATH))

    TaintForest(str(GOOD_FOREST_PATH), canonical_mapping=canonical_mapping()).validate(full=True)
