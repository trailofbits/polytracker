import pytest

from polytracker.database import DBProgramTrace


def test_db_schema():
    """Make sure the db schema is correct by loading it in memory"""
    DBProgramTrace.load(":memory:")
