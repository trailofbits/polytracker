from polyprocess import PolyProcess
import pytest
import logging
from typing import List
import networkx as nx
import os
import json

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

    con_comp = list(nx.strongly_connected_components(poly_proc.taint_forest))
    assert len(con_comp) == poly_proc.max_node()
    # for every canonical label, confirm it has no parents.
    for function in poly_proc.taint_sets:
        label_set: List[int] = poly_proc.taint_sets[function]["input_bytes"]
        for label in label_set:
            assert label <= max_node
            if poly_proc.is_canonical_label(label):
                parents = list(nx.dfs_preorder_nodes(poly_proc.taint_forest, label))
                assert len(parents) == 1


def test_polyprocess_taint_sets(json_path, forest_path):
    logger.info("Testing taint set processing")
    poly_proc = PolyProcess(json_path, forest_path)
    poly_proc.process_taint_sets()
    poly_proc.set_output_filepath("/tmp/polytracker.json")
    poly_proc.output_processed_json()
    assert os.path.exists("/tmp/polytracker.json") is True
    with open("/tmp/polytracker.json", "r") as poly_json:
        json_size = os.path.getsize("/tmp/polytracker.json")
        polytracker_json = json.loads(poly_json.read(json_size))
        if "tainted_functions" in poly_proc.polytracker_json:
            assert "tainted_functions" in polytracker_json
            for func in poly_proc.polytracker_json["tainted_functions"]:
                if "cmp_bytes" in poly_proc.polytracker_json["tainted_functions"][func]:
                    assert "cmp_bytes" in polytracker_json["tainted_functions"][func]
                if "input_bytes" in poly_proc.polytracker_json["tainted_functions"][func]:
                    assert "input_bytes" in polytracker_json["tainted_functions"][func]
        assert "version" in polytracker_json
        assert polytracker_json["version"] == poly_proc.polytracker_json["version"]
        assert "runtime_cfg" in polytracker_json
        assert len(polytracker_json["runtime_cfg"]["main"]) == 1
        assert "taint_sources" in polytracker_json
        assert "canonical_mapping" not in polytracker_json
        assert "tainted_input_blocks" in polytracker_json
