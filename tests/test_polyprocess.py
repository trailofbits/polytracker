from polyprocess import PolyProcess
import pytest
import logging
from typing import List
import networkx as nx
import os

logger = logging.getLogger("polyprocess_test:")
cwd = os.getcwd()


#############################
#      Tests go here        #
#############################

def test_polyprocess_creation(json_path, forest_path):
    logger.info("Testing PolyProcess object creation")

    with pytest.raises(ValueError):
        assert PolyProcess("BAD PATH", forest_path)
        assert PolyProcess(json_path, "BAD PATH")
    # This implicitly tests to make sure that no error is raised
    PolyProcess(json_path, forest_path)


def test_polyprocess_bad_forest(json_path):
    bad_forest_path = cwd + "/tests/test_data/bad_forest.bin"
    with pytest.raises(Exception):
        assert PolyProcess(json_path, bad_forest_path)


def test_polyprocess_forest(json_path, forest_path):
    logger.info("Testing forest processing")
    poly_proc = PolyProcess(json_path, forest_path)

    # Validate that the process sets conform to the taint forest given
    # Meaning that the polyprocess max label should be == to the highest val in the canonical map
    # If this fails, it could mean that there is an error in polytracker with label keeping
    # I am writing this test specifically to catch an off by one error caused by a taint union refactor
    max_node = poly_proc.max_node()
    # for every canonical label, confirm it has no parents.
    for function in poly_proc.taint_sets:
        label_set: List[int] = poly_proc.taint_sets[function]["input_bytes"]
        for label in label_set:
            assert label <= max_node
            if poly_proc.is_canonical_label(label):
                parents = list(nx.dfs_preorder_nodes(poly_proc.taint_forest, label))
                assert len(parents) == 1

    # Check for cycles in the graph
    with pytest.raises(nx.exception.NetworkXNoCycle):
        nx.find_cycle(poly_proc.taint_forest)


def test_polyprocess_has_version(json_path, forest_path):
    poly_proc = PolyProcess(json_path, forest_path)
    assert "version" in poly_proc.polytracker_json
    assert "runtime_cfg" in poly_proc.polytracker_json


def test_polyprocess_taint_sets(json_path, forest_path):
    logger.info("Testing taint set processing")
    poly_proc = PolyProcess(json_path, forest_path)
    poly_proc.process_taint_sets()
    poly_proc.set_output_filepath("/tmp/polytracker.json")
    poly_proc.output_processed_json()
    assert os.path.exists("/tmp/polytracker.json") is True
