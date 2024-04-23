#!/usr/bin/env python3

from ..analysis import Analysis, CachingTDAGTraverser, CFLog, CFLogEntry
from json import load
from pathlib import Path
from polytracker import PolyTrackerTrace, TDProgramTrace, TDFile, taint_dag
from polytracker.mapping import InputOutputMapping

import pytest
from typing import Dict, Iterable, List, Set, Tuple


class TestAnalysis:
    analysis = Analysis()

    @pytest.fixture
    def tdProgramTrace(self, tdag) -> TDProgramTrace:
        return PolyTrackerTrace.load(tdag)

    @pytest.fixture
    def functionid_json(self, json):
        with open(Path(json)) as json_file:
            return load(json_file)

    @pytest.fixture
    def tdProgramTrace2(self, tdag2) -> TDProgramTrace:
        """Since we are testing a comparator, sometimes we need
        two traces!"""
        return PolyTrackerTrace.load(tdag2)

    @pytest.fixture
    def functionid_json2(self, json2):
        with open(Path(json2)) as json_file:
            return load(json_file)

    def test_get_cflog(self, tdProgramTrace, functionid_json):
        cflog: CFLog = self.analysis.get_cflog(tdProgramTrace.tdfile, functionid_json)

        for entry in cflog.entries:
            assert type(entry) == CFLogEntry
            assert len(entry.input_bytes) >= 1

            for byte_offset in entry.input_bytes:
                assert byte_offset >= 0

            assert len(entry.callstack) >= 1

            for callstack_entry in entry.callstack:
                assert type(callstack_entry) == str

    def test_interleave_file_cavities(self, tdProgramTrace, functionid_json):
        cflog: CFLog = self.analysis.get_cflog(
            tdProgramTrace.tdfile, functionid_json, with_cavities=True
        )

        for prev, entry in zip(() + cflog.entries[:-1], cflog.entries):
            assert entry is not None
            if prev is not None and prev.callstack is None:
                assert prev.input_bytes[-1] <= entry.input_bytes[0]
                assert prev.input_bytes[-1] <= entry.input_bytes[-1]

        for entry, next in zip(cflog.entries, cflog.entries[1:] + ()):
            assert entry is not None
            if next is not None and entry.callstack is None:
                assert entry.input_bytes[-1] <= next.input_bytes[0]
                assert entry.input_bytes[-1] <= next.input_bytes[-1]

        cflog_no_cavities: CFLog = self.analysis.get_cflog(
            tdProgramTrace.tdfile, functionid_json, with_cavities=False
        )

        assert len(cflog.entries) > len(cflog_no_cavities.entries)

        file_cavities_raw = InputOutputMapping(tdProgramTrace.tdfile).file_cavities()
        for file_path in file_cavities_raw:
            cavities = file_cavities_raw[file_path]
            assert len(cavities) > 0
            for byte_set in cavities:
                # ensure we didn't drop the last few accidentally even if they are "off the end" of the cflog ie end of input file unused
                assert CFLogEntry.cavity(byte_set) in cflog

    def test_get_lookahead_only_differential_entries(
        self,
        tdProgramTrace: TDProgramTrace,
        tdProgramTrace2: TDProgramTrace,
        functionid_json,
        functionid_json2,
    ):
        cflogA = self.analysis.get_cflog(tdProgramTrace.tdfile, functionid_json)
        cflogB = self.analysis.get_cflog(tdProgramTrace2.tdfile, functionid_json2)
        assert len(cflogA.entries) != len(cflogB.entries)

        diff: Iterable = self.analysis.get_differential_entries(
            cflogA, cflogB, use_graphtage=False
        )

        for entry in diff:
            # TODO: test when we SHOULD step
            if type(entry[0]) == CFLogEntry and type(entry[1]) == CFLogEntry:
                if entry[0].input_bytes != entry[1].input_bytes:
                    # if bytes don't match up, we stepped things so they "match", earlier
                    assert entry[0] is None or entry[1] is None
                if entry[0].callstack != entry[1].callstack:
                    # if callstack doesn't match, bytes should still match,
                    # or we previously stepped
                    assert (
                        entry[0].input_bytes == entry[1].input_bytes
                        or entry[0] is None
                        or entry[1] is None
                    )
                # while every entry in the diff should show up in the result, every entry in each cflog MAY NOT show up in the diff due to skipping
                assert entry[0] in cflogA.entries
                assert entry[1] in cflogB.entries
            else:
                assert type(entry[0]) == type(None) or type(entry[1]) == type(None)

    @pytest.mark.skip(
        reason="This test on a well provisioned DO VM currently takes over 12 hours to complete with two NITF tdags (where lookahead-only analysis completed in a couple minutes)"
    )
    def test_get_differential_entries(
        self,
        tdProgramTrace: TDProgramTrace,
        tdProgramTrace2: TDProgramTrace,
        functionid_json,
        functionid_json2,
    ):
        print(
            "Warning: test_get_differential_entries is very slow since we load two whole TDAGs into Graphtage; expect to see some progress bars"
        )

        cflogA: CFLog = self.analysis.get_cflog(tdProgramTrace.tdfile, functionid_json)
        cflogB: CFLog = self.analysis.get_cflog(
            tdProgramTrace2.tdfile, functionid_json2
        )

        diff_without_graphtage: Iterable = self.analysis.get_differential_entries(
            cflogA, cflogB, use_graphtage=False
        )

        diff_with_graphtage: Iterable = self.analysis.get_differential_entries(
            cflogA, cflogB, use_graphtage=True
        )

        # graphtage matches BOTH in the forward and backward directions;
        # note that our algorithm from the ubet paper only matched forward
        assert len(tuple(diff_without_graphtage)) <= len(tuple(diff_with_graphtage))

        for wo_graph_entry in diff_without_graphtage:
            assert wo_graph_entry in diff_with_graphtage

    def test_same_equality(
        self,
        tdProgramTrace: TDProgramTrace,
        tdProgramTrace2: TDProgramTrace,
        functionid_json,
        functionid_json2,
    ):

        cflogA: CFLog = self.analysis.get_cflog(tdProgramTrace.tdfile, functionid_json)
        cflogB: CFLog = self.analysis.get_cflog(
            tdProgramTrace2.tdfile, functionid_json2
        )

        # for each of our test tdags, check that diffing the tdag against itself produces no differences
        diffA: Iterable = self.analysis.get_differential_entries(
            cflogA, cflogA, use_graphtage=True
        )

        for entry in diffA:
            assert entry[0] == entry[1]

        diffB: Iterable = self.analysis.get_differential_entries(
            cflogB, cflogB, use_graphtage=True
        )

        for entry in diffB:
            assert entry[0] == entry[1]

    @pytest.mark.skip(
        reason="This test on a well provisioned DO VM currently takes over 12 hours to complete with two NITF tdags (where lookahead-only analysis completed in a couple minutes)"
    )
    def test_find_divergence(
        self,
        tdProgramTrace: TDProgramTrace,
        tdProgramTrace2: TDProgramTrace,
        functionid_json,
        functionid_json2,
    ):
        trace, bytes_operated_from, bytes_operated_to = self.analysis.find_divergence(
            from_tdag=tdProgramTrace.tdfile,
            to_tdag=tdProgramTrace2.tdfile,
            from_functions_list=functionid_json,
            to_functions_list=functionid_json2,
        )

        assert len(bytes_operated_from) > 0
        assert len(bytes_operated_to) > 0

        for diff_entry in trace:
            assert diff_entry[1] != diff_entry[2]
