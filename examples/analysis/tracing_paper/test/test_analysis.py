#!/usr/bin/env python3

from ..analysis import Analysis, CachedTDAGTraverser, CFLog, CFLogEntry
from json import load
from pathlib import Path
from polytracker import PolyTrackerTrace, TDProgramTrace, taint_dag
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
        return load(Path(json).open())

    @pytest.fixture
    def tdProgramTrace2(self, tdag2) -> TDProgramTrace:
        """Since we are testing a comparator, sometimes we need
        two traces!"""
        return PolyTrackerTrace.load(tdag2)

    @pytest.fixture
    def functionid_json2(self, json2):
        return load(Path(json2).open())

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

    def test_stringify_list(self):
        l1 = self.analysis.stringify_list(None)
        assert l1 == ""

        l2 = self.analysis.stringify_list([1])
        assert l2 == "1"

        l3 = self.analysis.stringify_list(["f()", "g(int *i)"])
        assert l3 == "f(), g(int *i)"

        l4 = self.analysis.stringify_list([45, 46, 51])
        assert l4 == "45, 46, 51"

        l5 = self.analysis.stringify_list(["whatAGreatFn(...)"])
        assert l5 == "whatAGreatFn(...)"

        l6 = self.analysis.stringify_list("")
        assert l6 == ""

        l7 = self.analysis.stringify_list([""])
        assert l7 == ""

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

    # def test_get_differential_entries(
    #     self,
    #     tdProgramTrace: TDProgramTrace,
    #     tdProgramTrace2: TDProgramTrace,
    #     functionid_json,
    #     functionid_json2,
    # ):
    #     print("Warning: this test is very slow; expect to see some progress bars")

    #     cflogA: CFLog = self.analysis.get_cflog(
    #         tdProgramTrace.tdfile, functionid_json
    #     )
    #     cflogB: CFLog = self.analysis.get_cflog(
    #         tdProgramTrace2.tdfile, functionid_json2
    #     )

    #     diff_without_graphtage: Iterable = self.analysis.get_differential_entries(
    #         cflogA, cflogB, use_graphtage=False
    #     )

    #     diff_with_graphtage: Iterable = self.analysis.get_differential_entries(
    #         cflogA, cflogB, use_graphtage=True
    #     )

    #     # graphtage matches BOTH in the forward and backward directions;
    #     # note that our algorithm from the ubet paper only matched forward
    #     assert len(tuple(diff_without_graphtage)) <= len(tuple(diff_with_graphtage))

    #     for wo_graph in diff_without_graphtage:
    #         assert wo_graph in diff_with_graphtage

    # def test_interleaved_differential(
    #     self,
    #     tdProgramTrace: TDProgramTrace,
    #     tdProgramTrace2: TDProgramTrace,
    #     functionid_json,
    #     functionid_json2,
    # ):
    #     cflogA = self.analysis.get_cflog(
    #         tdProgramTrace.tdfile, functionid_json
    #     )
    #     cflogB = self.analysis.get_cflog(
    #         tdProgramTrace2.tdfile, functionid_json2
    #     )
    #     differential: Iterable = tuple(
    #         self.analysis.get_differential_entries(cflogA, cflogB, use_graphtage=False)
    #     )
    #     interleaved_cflog_A: CFLog = self.analysis.interleave_file_cavities(
    #         tdProgramTrace.tdfile, cflogA
    #     )
    #     interleaved_cflog_B: CFLog = self.analysis.interleave_file_cavities(
    #         tdProgramTrace2.tdfile, cflogB
    #     )
    #     cavitatious_differential: Iterable = tuple(
    #         self.analysis.get_differential_entries(
    #             interleaved_cflog_A, interleaved_cflog_B, use_graphtage=False
    #         )
    #     )
    #     assert len(cavitatious_differential) >= len(differential)

    # cflog_A_offsets_plus_cavities = [entry[0] for entry in cavitatious_differential]
    # cflog_A_callstacks_plus_cavities = [
    #     entry[1] for entry in cavitatious_differential
    # ]
    # for entry in interleaved_cflog_A:
    #     assert entry.input_bytes in cflog_A_offsets_plus_cavities
    #     if entry.callstack is not None and len(entry.callstack) > 0:
    #         assert entry.callstack[-1] in cflog_A_callstacks_plus_cavities

    # cflog_B_offsets_plus_cavities = [entry[3] for entry in cavitatious_differential]
    # cflog_B_callstacks_plus_cavs = [entry[2] for entry in cavitatious_differential]
    # for entry in interleaved_cflog_B:
    #     assert entry.input_bytes in cflog_B_offsets_plus_cavities
    #     if entry.callstack is not None and len(entry.callstack) > 0:
    #         assert entry.callstack[-1] in cflog_B_callstacks_plus_cavs

    # def test_same_comparison_differential(
    #     self,
    #     tdProgramTrace: TDProgramTrace,
    #     functionid_json,
    # ):
    #     """Ensure we are internally consistent."""
    #     cflogA: Tuple[CFLogEntry, ...] = self.analysis.get_cflog(
    #         tdProgramTrace.tdfile, functionid_json
    #     ).entries
    #     cflogB: Tuple[CFLogEntry, ...] = self.analysis.get_cflog(
    #         tdProgramTrace.tdfile, functionid_json
    #     ).entries
    #     assert len(cflogA) == len(cflogB)

    #     for entryA, entryB in zip(cflogA, cflogB):
    #         assert len(entryA.input_bytes) == len(entryB.input_bytes)
    #         assert entryA.input_bytes == entryB.input_bytes
    #         assert len(entryA.callstack) == len(entryB.callstack)
    #         assert entryA.callstack == entryB.callstack

    #     differential = self.analysis.get_differential_entries(cflogA, cflogB)
    #     # assert len(differential) >= len(cflogA)

    #     for entry in differential:
    #         # byte sets are the same
    #         assert entry[0] == entry[3]
    #         # call stacks are the same
    #         assert entry[1] == entry[2]
