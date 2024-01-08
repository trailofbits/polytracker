import pytest
from polytracker import PolyTrackerTrace, taint_dag
import polytracker
from pathlib import Path
from ..comparator import TdagComparator
from json import load


class TestCompareTdags:
    @pytest.fixture
    def comparator(self):
        return TdagComparator()

    @pytest.fixture
    def tdfile(self, tdag):
        return PolyTrackerTrace.load(tdag).tdfile

    @pytest.fixture
    def get_functionid_json(self, json_path):
        return load(json_path)

    def test__sorted_input_offsets(self, tdfile, comparator):
        cflog = tdfile._get_section(taint_dag.TDControlFlowLogSection)

        for control_flow_event in cflog:
            if isinstance(control_flow_event, taint_dag.TDTaintedControlFlowEvent):
                sorted_offsets = comparator.sorted_input_offsets(
                    control_flow_event.label, tdfile
                )
                assert len(sorted_offsets) > 0
                assert sorted(sorted_offsets) == sorted_offsets
