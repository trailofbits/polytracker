import pytest

from polytracker.database import DBPolyTrackerTrace


def test_db_schema():
    """Make sure the db schema is correct by loading it in memory"""
    DBPolyTrackerTrace.load(":memory:")
