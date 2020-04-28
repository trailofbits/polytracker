from dataclasses import dataclass
from logging import Logger
from tqdm import tqdm
import struct
import logging
import os
from subprocess import check_call
import networkx as nx
import json
from networkx.drawing.nx_pydot import write_dot
from typing import List, Dict
from typing_extensions import Final

logger: Logger = logging.getLogger("PolyProcess")

"""
This "Final" type means this is just a const 13
Final is in python 3.8, currently this is 3.7
This 13 is the size (bytes) of the taint node struct defined in dfsan_types.h
"""
taint_node_size: Final[int] = 13
taint_header_size: Final[int] = 9


@dataclass
class TaintMetadata:
    decay_val: int
    taint_source: int


@dataclass
class SourceMetadata:
    taint_range_start: int
    taint_range_end: int


class Polyprocess:
    """This is the PolyProcess class

    This class takes two arguments

    1. PolyTracker produced json containing CFG, taint sets, and version number. (PolyMerge has better version parsing)

    2. PolyTracker raw taint forest

    PolyProcess will take these files and:

    1. Reconstruct the CFG, taint forest and taint sets

    2. Process the taint sets to produce a final json containing the byte offsets touched in each function
    """
    def __init__(self, polytracker_json_path: str, polytracker_forest_path: str):
        if polytracker_json_path is None or polytracker_forest_path is None:
            raise ValueError("Error: Path cannot be None")
        if not os.path.exists(polytracker_json_path):
            raise ValueError("Error: Could not find polytracker json path")
        if not os.path.exists(polytracker_forest_path):
            raise ValueError("Error: Could not find polytracker forest path")

        self.json_file = open(polytracker_json_path, "r")
        self.json_size = os.path.getsize(polytracker_json_path)
        self.polytracker_json = json.loads(self.json_file.read(self.json_size))
        self.taint_sets = self.polytracker_json["tainted_functions"]
        self.forest_file = open(polytracker_forest_path, "rb")
        self.forest_file_size = os.path.getsize(polytracker_forest_path)
        # Actual taint forest
        self.taint_forest: nx.DiGraph = nx.DiGraph()

        # Stores info about taint source.
        self.taint_metadata: Dict[int, TaintMetadata] = {}
        self.source_metadata: Dict[int, SourceMetadata] = {}
        self.process_forest()
        self.outfile = "polytracker.json"

    def print_header(self):
        self.forest_file.seek(0)
        num_taint_sources = struct.unpack("=I", self.forest_file.read(4))
        print("=" * 9, "TAINT HEADER", "=" * 9)
        print(f"num taint sources: {num_taint_sources[0]}")
        for i in range(num_taint_sources[0]):
            taint_header_entry = struct.unpack("=cII", self.forest_file.read(taint_header_size))
            taint_source_id: int = taint_header_entry[0]
            taint_source_start: int = taint_header_entry[1]
            taint_source_end: int = taint_header_entry[2]
            print("TAINT_ENTRY: ", taint_source_id, taint_source_start, taint_source_end)
        print("="*32)

    def validate_forest(self, num_taint_sources) -> bool:
        header_size = (num_taint_sources * taint_header_size) + 4
        forest_size = taint_node_size * self.max_node()
        res = self.forest_file_size - (header_size + forest_size) == 0
        return res

    def max_node(self):
        return (self.forest_file_size // taint_node_size) - 1

    def process_taint_header(self):
        logger.debug("Processing taint header")
        self.forest_file.seek(0)
        num_taint_sources = struct.unpack("=I", self.forest_file.read(4))
        num_taint_sources = num_taint_sources[0]
        is_valid = self.validate_forest(num_taint_sources)
        if not is_valid:
            raise Exception("Invalid taint forest")
        if num_taint_sources <= 0:
            raise Exception("Invalid taint header - no sources!")
        for i in range(num_taint_sources):
            taint_header_entry = struct.unpack("=cII", self.forest_file.read(taint_header_size))
            taint_source_id: int = taint_header_entry[0]
            taint_source_start: int = taint_header_entry[1]
            taint_source_end: int = taint_header_entry[2]
            self.source_metadata[taint_source_id] = SourceMetadata(taint_source_start, taint_source_end)

    def process_forest(self):
        """This function reads the taint forest file and converts it to a networkX graph

        The taint forest file is a bunch of raw bytes, where each sizeof(dfsan_label) chunk
        represents a taint_node struct. The actual definition of the struct can be found in
        include/dfsan_types.h

        The function that produces this taint forest is outputRawTaintForest

        Note that the taint info here (and anything of type label) is 1 indexed, because 0 is the null index.

        The way we convert back to canonical bytes is by travelling up the forest to a node with two null parents
        Then subtract one from that label, which gets you the original offset.
        """
        logger.log(logging.DEBUG, "Processing taint forest!")
        # Add the null node
        self.taint_forest.add_node(0)
        self.taint_metadata[0] = TaintMetadata(0, 0)

        try:
            self.process_taint_header()
        except Exception:
            raise

        for curr_node in range(self.max_node()):
            taint_forest_entry = struct.unpack("=IIcI", self.forest_file.read(taint_node_size))
            parent_1: int = taint_forest_entry[0]
            parent_2: int = taint_forest_entry[1]
            taint_source = taint_forest_entry[2]
            decay: int = taint_forest_entry[3]
            self.taint_forest.add_node(curr_node + 1)
            # Parents for canonical labels should have parents of label 0
            self.taint_metadata[curr_node + 1] = TaintMetadata(decay, taint_source)
            if parent_1 != 0 and parent_2 != 0:
                self.taint_forest.add_edge(curr_node + 1, parent_1)
                self.taint_forest.add_edge(curr_node + 1, parent_2)

    def draw_forest(self):
        logger.log(logging.DEBUG, "Drawing forest")
        pos = nx.nx_agraph.graphviz_layout(self.taint_forest)
        nx.draw(self.taint_forest, pos=pos)
        write_dot(self.taint_forest, "taint_forest.dot")
        check_call(['dot', '-Tpng', 'taint_forest.dot', '-o', 'taint_forest.pdf'])

    def is_canonical(self, label):
        # Taint source id
        taint_id = self.taint_metadata[label].taint_source
        # Taint range
        source_data = self.source_metadata[taint_id]
        return source_data.taint_range_start <= (label - 1) <= source_data.taint_range_end

    def process_taint_sets(self):
        taint_sets = tqdm(self.taint_sets)
        processed_sets = {}
        for function in taint_sets:
            taint_sets.set_description(f"Processing {function}")
            for source in self.taint_sets[function]["input_bytes"]:
                label_set: List[int] = self.taint_sets[function]["input_bytes"][source]
                processed_sets[function] = {"input_bytes": {source: list()}}
                for label in label_set:
                    preds = list(set(
                        label for label in nx.dfs_preorder_nodes(self.taint_forest, label)
                        if self.is_canonical(label)
                    ))
                    canonical_labels = [x - 1 for x in preds]
                    processed_sets[function]["input_bytes"][source] += canonical_labels
                    processed_sets[function]["input_bytes"][source] = list(
                        set(processed_sets[function]["input_bytes"][source]))

        self.polytracker_json["tainted_functions"] = processed_sets
        with open(self.outfile, 'w') as out_fd:
            json.dump(self.polytracker_json, out_fd, indent=4)
