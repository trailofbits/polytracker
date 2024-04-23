#!/usr/bin/env python3

from ..traverser import CachingTDAGTraverser
from json import load
from pathlib import Path
from polytracker import PolyTrackerTrace, TDFile, taint_dag
import pytest


class TestTraverser:
    @pytest.fixture
    def tdfile(self, tdag) -> TDFile:
        return PolyTrackerTrace.load(tdag).tdfile

    def test_cache_fetch(self, tdfile):
        traverser = CachingTDAGTraverser(tdfile)
        cflog_tdag_section = tdfile._get_section(taint_dag.TDControlFlowLogSection)

        for cflog_entry in cflog_tdag_section:
            if not isinstance(cflog_entry, taint_dag.TDTaintedControlFlowEvent):
                continue
            traverser[cflog_entry.label]
            assert cflog_entry.label in traverser._cache

    def test_cache_sizing(self, tdfile):
        max_size = 5
        traverser = CachingTDAGTraverser(tdfile, max_size)
        cflog_tdag_section = tdfile._get_section(taint_dag.TDControlFlowLogSection)

        for cflog_entry in cflog_tdag_section:
            if not isinstance(cflog_entry, taint_dag.TDTaintedControlFlowEvent):
                continue
            traverser[cflog_entry.label]
            assert len(traverser._cache) <= max_size + 1
