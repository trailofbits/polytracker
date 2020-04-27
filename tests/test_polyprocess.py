from polyprocess import Polyprocess
import pytest
import logging
from typing import List
import networkx as nx

logger = logging.getLogger("polyprocess_test:")


#############################
#      Tests go here        #
#############################

def test_polyprocess_creation(json_path, forest_path):
    logger.info("Testing PolyProcess object creation")

    with pytest.raises(ValueError):
        assert Polyprocess("BAD PATH", forest_path)
        assert Polyprocess(json_path, "BAD PATH")
    # This implicitly tests to make sure that no error is raised
    Polyprocess(json_path, forest_path)


def test_polyprocess_forest(json_path, forest_path):
    logger.info("Testing forest processing")
    polyproc = Polyprocess(json_path, forest_path)
    polyproc.process_forest()

    # for every canonical label, confirm it has no parents.
    for function in polyproc.taint_sets:
        for source in polyproc.taint_sets[function]["input_bytes"]:
            label_set: List[int] = polyproc.taint_sets[function]["input_bytes"][source]
            for label in label_set:
                if polyproc.is_canonical(label):
                    parents = list(nx.dfs_preorder_nodes(polyproc.taint_forest, label))
                    assert len(parents) == 1

    # Check for cycles in the graph
    with pytest.raises(nx.exception.NetworkXNoCycle):
        nx.find_cycle(polyproc.taint_forest)
