import pytest
from polytracker import PolyTrackerTrace, taint_dag
import polytracker
from pathlib import Path
from ..compare_tdags import input_offsets
from json import load


class TestCompareTdags:
    @pytest.fixture
    def get_tdag(self, tdag):
        return PolyTrackerTrace.load(tdag)

    @pytest.fixture
    def get_functionid_json(self, json_path):
        return load(json_path)

    def test_input_offsets(self, tdag):
        cflog = self.get_tdag(tdag)._get_section(taint_dag.TDControlFlowLogSection)

        for control_flow_event in cflog:
            if isinstance(control_flow_event, taint_dag.TDTaintedControlFlowEvent):
                sorted_offsets = input_offsets(tdag, control_flow_event.label)
                assert -1 not in sorted_offsets.keys()
