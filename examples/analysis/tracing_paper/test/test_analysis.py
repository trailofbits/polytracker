from ..analysis import Analysis
from json import load
from pathlib import Path
from polytracker import InputOutputMapping, PolyTrackerTrace, TDProgramTrace, taint_dag
import pytest
from typing import Dict, List, Set, Tuple


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

    def test_node_equals(self):
        source1 = taint_dag.TDSourceNode(0, 23, True)
        source2 = taint_dag.TDSourceNode(0, 23, False)
        source3 = taint_dag.TDSourceNode(52, 23, False)
        source4 = taint_dag.TDSourceNode(0, 100, True)
        assert not self.analysis.node_equals(source1, source2)
        assert self.analysis.node_equals(source1, source1)
        assert not self.analysis.node_equals(source3, source2)
        assert not self.analysis.node_equals(source4, source1)

        union1 = taint_dag.TDUnionNode(0, 23, True)
        union2 = taint_dag.TDUnionNode(0, 23, False)
        assert not self.analysis.node_equals(source1, union1)
        assert not self.analysis.node_equals(source2, union2)
        assert not self.analysis.node_equals(union1, union2)
        assert self.analysis.node_equals(union1, union1)

        union3 = taint_dag.TDUnionNode(13, 23, False)
        union4 = taint_dag.TDUnionNode(0, 8, True)
        assert not self.analysis.node_equals(union3, union2)
        assert not self.analysis.node_equals(union4, union1)

        range1 = taint_dag.TDRangeNode(0, 23, True)
        range2 = taint_dag.TDRangeNode(0, 23, False)
        assert not self.analysis.node_equals(source1, range1)
        assert not self.analysis.node_equals(union1, range1)
        assert not self.analysis.node_equals(range1, range2)
        assert self.analysis.node_equals(range1, range1)

        range3 = taint_dag.TDRangeNode(32, 53, False)
        range4 = taint_dag.TDRangeNode(5, 23, True)
        assert not self.analysis.node_equals(range3, range2)
        assert not self.analysis.node_equals(range4, range1)

        untainted1 = taint_dag.TDUntaintedNode()
        assert not self.analysis.node_equals(source1, untainted1)
        assert not self.analysis.node_equals(union1, untainted1)
        assert not self.analysis.node_equals(range1, untainted1)
        assert self.analysis.node_equals(untainted1, untainted1)

    def test_input_offsets(self, tdProgramTrace: TDProgramTrace):
        cflog = tdProgramTrace.tdfile._get_section(taint_dag.TDControlFlowLogSection)

        for cf_event in cflog:
            if isinstance(cf_event, taint_dag.TDTaintedControlFlowEvent):
                computed_offsets: Dict[
                    int, List[taint_dag.TDNode]
                ] = self.analysis.input_offsets(tdProgramTrace.tdfile)
                assert len(computed_offsets) >= 1

                for offset, node_set in computed_offsets.items():
                    assert offset in list(map(lambda node: node.offset, node_set))
                    # should be no duplicates
                    assert len(node_set) == len(set(node_set))

    def test_ancestor_input_set(self, tdProgramTrace: TDProgramTrace):
        input_set: Set[taint_dag.TDNode] = self.analysis.ancestor_input_set(
            13, tdProgramTrace.tdfile
        )
        assert tdProgramTrace.tdfile.label_count > len(input_set)

        tdfile_input_offsets: List[int] = list(tdProgramTrace.tdfile.input_labels())

        node: taint_dag.TDNode
        for node in input_set:
            assert isinstance(node, taint_dag.TDSourceNode)
            # each should have been in the source section
            assert node.offset in tdfile_input_offsets

    def test_sorted_ancestor_offsets(self, tdProgramTrace: TDProgramTrace):
        cflog = tdProgramTrace.tdfile._get_section(taint_dag.TDControlFlowLogSection)

        for cf_event in cflog:
            if isinstance(cf_event, taint_dag.TDTaintedControlFlowEvent):
                sorted_offsets: List[int] = self.analysis.sorted_ancestor_offsets(
                    cf_event.label, tdProgramTrace.tdfile
                )
                # each cflog entry label should map to at least one ancestor input byte label / offset
                assert len(sorted_offsets) >= 1

    def test_interleave_file_cavities(self, tdProgramTrace, functionid_json):
        cflog = self.analysis.get_cflog_entries(tdProgramTrace.tdfile, functionid_json)

        interleaved = self.analysis.interleave_file_cavities(
            tdProgramTrace.tdfile, cflog
        )
        assert len(interleaved) > len(cflog)
        byte_side_entries = list(map(lambda entry: entry[0], interleaved))

        file_cavities_raw = InputOutputMapping(tdProgramTrace.tdfile).file_cavities()
        for file_name in file_cavities_raw:
            cavities = map(
                lambda byte_set: f"CAVITY [{byte_set[0]}, {byte_set[1]})",
                file_cavities_raw[file_name],
            )
            for cavity in cavities:
                # ensure we didn't drop the last few accidentally even if they are "off the end" of the cflog ie end of input file unused
                assert cavity in byte_side_entries

    def test_get_cflog_entries(self, tdProgramTrace, functionid_json):
        """LHS should be List[str | int]: a list of byte offsets, or an exclusive/inclusive cavity range. RHS should be List[str]: the callstack."""
        entries = self.analysis.get_cflog_entries(
            tdProgramTrace.tdfile, functionid_json
        )

        for entry in entries:
            assert len(entry[0]) >= 1

            for byte_offset in entry[0]:
                assert byte_offset >= 0

            assert len(entry[1]) >= 1

            for callstack_entry in entry[1]:
                assert type(callstack_entry) == str

    def test_stringify_list(self):
        l1 = self.analysis.stringify_list(None)
        assert l1 == ""

        l2 = self.analysis.stringify_list([1])
        assert l2 == "[1]"

        l3 = self.analysis.stringify_list(["f()", "g(int *i)"])
        assert l3 == "['f()', 'g(int *i)']"

        l4 = self.analysis.stringify_list([45, 46, 51])
        assert l4 == "[45, 46, 51]"

        l5 = self.analysis.stringify_list(["whatAGreatFn(...)"])
        assert l5 == "['whatAGreatFn(...)']"

        l6 = self.analysis.stringify_list("")
        assert l6 == ""

        l7 = self.analysis.stringify_list([""])
        assert l7 == "['']"

    def test_get_differential_entries(
        self,
        tdProgramTrace: TDProgramTrace,
        tdProgramTrace2: TDProgramTrace,
        functionid_json,
        functionid_json2,
    ):
        cflogA = self.analysis.get_cflog_entries(tdProgramTrace.tdfile, functionid_json)
        cflogB = self.analysis.get_cflog_entries(
            tdProgramTrace2.tdfile, functionid_json2
        )
        differential = self.analysis.get_differential_entries(cflogA, cflogB)
        assert len(differential) >= len(cflogA)
        assert len(differential) >= len(cflogB)

        for entry in differential:
            if entry[0] != entry[3]:
                # if bytes don't match up, we stepped things so they "match" earlier
                assert entry[0] is None or entry[3] is None
            if entry[1] != entry[2]:
                # if callstack doesn't match, bytes should still match,
                # or we stepped
                assert entry[0] == entry[3] or entry[0] is None or entry[3] is None

        computed_cflogA_aligned_offsets = [entry[0] for entry in differential]
        computed_cflogA_callstacks = [entry[1] for entry in differential]
        for entry in cflogA:
            assert entry[0] in computed_cflogA_aligned_offsets
            if entry[1] is not None and len(entry[1]) > 0:
                assert entry[1][-1] in computed_cflogA_callstacks

        computed_cflogB_aligned_offsets = [entry[3] for entry in differential]
        computed_cflogB_callstacks = [entry[2] for entry in differential]
        for entry in cflogB:
            assert entry[0] in computed_cflogB_aligned_offsets
            if entry[1] is not None and len(entry[1]) > 0:
                assert entry[1][-1] in computed_cflogB_callstacks

    def test_interleaved_differential(
        self,
        tdProgramTrace: TDProgramTrace,
        tdProgramTrace2: TDProgramTrace,
        functionid_json,
        functionid_json2,
    ):
        cflogA = self.analysis.get_cflog_entries(tdProgramTrace.tdfile, functionid_json)
        cflogB = self.analysis.get_cflog_entries(
            tdProgramTrace2.tdfile, functionid_json2
        )
        differential = self.analysis.get_differential_entries(cflogA, cflogB)
        interleaved_cflog_A = self.analysis.interleave_file_cavities(
            tdProgramTrace.tdfile, cflogA
        )
        interleaved_cflog_B = self.analysis.interleave_file_cavities(
            tdProgramTrace2.tdfile, cflogB
        )
        cavitatious_differential = self.analysis.get_differential_entries(
            interleaved_cflog_A, interleaved_cflog_B
        )
        assert len(cavitatious_differential) > len(differential)

        cflog_A_offsets_plus_cavities = [entry[0] for entry in cavitatious_differential]
        cflog_A_callstacks_plus_cavities = [
            entry[1] for entry in cavitatious_differential
        ]
        for entry in interleaved_cflog_A:
            assert entry[0] in cflog_A_offsets_plus_cavities
            if entry[1] is not None and len(entry[1]) > 0:
                assert entry[1][-1] in cflog_A_callstacks_plus_cavities

        cflog_B_offsets_plus_cavities = [entry[3] for entry in cavitatious_differential]
        cflog_B_callstacks_plus_cavs = [entry[2] for entry in cavitatious_differential]
        for entry in interleaved_cflog_B:
            assert entry[0] in cflog_B_offsets_plus_cavities
            if entry[1] is not None and len(entry[1]) > 0:
                assert entry[1][-1] in cflog_B_callstacks_plus_cavs

    def test_same_comparison_differential(
        self,
        tdProgramTrace: TDProgramTrace,
        functionid_json,
    ):
        cflogA = self.analysis.get_cflog_entries(tdProgramTrace.tdfile, functionid_json)
        cflogB = self.analysis.get_cflog_entries(tdProgramTrace.tdfile, functionid_json)
        assert len(cflogA) == len(cflogB)

        for entryA, entryB in zip(cflogA, cflogB):
            assert entryA[0] == entryB[0]
            assert entryA[1] == entryB[1]

        differential = self.analysis.get_differential_entries(cflogA, cflogB)
        assert len(differential) >= len(cflogA)

        for entry in differential:
            assert entry[0] == entry[3]
            assert entry[1] == entry[2]

    def test_compare_run_trace(self, tdProgramTrace: TDProgramTrace):
        pass

    # def test_compare_enum_diff(
    #     self, tdProgramTrace: TDProgramTrace, tdProgramTrace2: TDProgramTrace
    # ):
    #     pass

    # def test_compare_inputs_used(
    #     self, tdProgramTrace: TDProgramTrace, tdProgramTrace2: TDProgramTrace
    # ):
    #     pass