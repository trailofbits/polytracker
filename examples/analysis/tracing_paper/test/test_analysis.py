import pytest
from polytracker import PolyTrackerTrace, taint_dag
import polytracker
from pathlib import Path
from ..analysis import Analysis
from json import load


class TestCompareTdags:
    comparator = Analysis()

    @pytest.fixture
    def tdfile(self, tdag):
        return PolyTrackerTrace.load(tdag).tdfile

    @pytest.fixture
    def functionid_json(self, json):
        return load(json)

    @pytest.fixture
    def tdfile2(self, tdag2):
        """Since we are testing a comparator, sometimes we need
        two traces!"""
        return PolyTrackerTrace.load(tdag2).tdfile

    @pytest.fixture
    def functionid_json2(self, json2):
        return load(json2)

    def test_node_equals(self):
        source1 = taint_dag.TDSourceNode(0, 23, True)
        source2 = taint_dag.TDSourceNode(0, 23, False)
        source3 = taint_dag.TDSourceNode(52, 23, False)
        source4 = taint_dag.TDSourceNode(0, 100, True)
        assert not self.comparator.node_equals(source1, source2)
        assert self.comparator.node_equals(source1, source1)
        assert not self.comparator.node_equals(source3, source2)
        assert not self.comparator.node_equals(source4, source1)

        union1 = taint_dag.TDUnionNode(0, 23, True)
        union2 = taint_dag.TDUnionNode(0, 23, False)
        assert not self.comparator.node_equals(source1, union1)
        assert not self.comparator.node_equals(source2, union2)
        assert not self.comparator.node_equals(union1, union2)
        assert self.comparator.node_equals(union1, union1)

        union3 = taint_dag.TDUnionNode(13, 23, False)
        union4 = taint_dag.TDUnionNode(0, 8, True)
        assert not self.comparator.node_equals(union3, union2)
        assert not self.comparator.node_equals(union4, union1)

        range1 = taint_dag.TDRangeNode(0, 23, True)
        range2 = taint_dag.TDRangeNode(0, 23, False)
        assert not self.comparator.node_equals(source1, range1)
        assert not self.comparator.node_equals(union1, range1)
        assert not self.comparator.node_equals(range1, range2)
        assert self.comparator.node_equals(range1, range1)

        range3 = taint_dag.TDRangeNode(32, 53, False)
        range4 = taint_dag.TDRangeNode(5, 23, True)
        assert not self.comparator.node_equals(range3, range2)
        assert not self.comparator.node_equals(range4, range1)

        untainted1 = taint_dag.TDUntaintedNode()
        assert not self.comparator.node_equals(source1, untainted1)
        assert not self.comparator.node_equals(union1, untainted1)
        assert not self.comparator.node_equals(range1, untainted1)
        assert self.comparator.node_equals(untainted1, untainted1)

    def test_input_set(self, tdfile):
        pass

    def test_input_offsets(self, tdfile):
        pass

    def test_sorted_input_offsets(self, tdfile):
        cflog = tdfile._get_section(taint_dag.TDControlFlowLogSection)

        for control_flow_event in cflog:
            if isinstance(control_flow_event, taint_dag.TDTaintedControlFlowEvent):
                sorted_offsets = self.comparator.sorted_input_offsets(
                    control_flow_event.label, tdfile
                )
                assert len(sorted_offsets) > 0
                assert sorted(sorted_offsets) == sorted_offsets

    def test_get_cflog_entries(self, tdfile):
        pass

    def test_interleave_file_cavities(self, tdfile):
        pass

    def test_compare_cflog(self, tdfile, tdfile2):
        pass

    def test_compare_run_trace(self, tdfile):
        pass

    def test_compare_enum_diff(self, tdfile, tdfile2):
        pass

    def test_compare_inputs_used(self, tdfile, tdfile2):
        pass
