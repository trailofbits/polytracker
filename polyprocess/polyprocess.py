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
from typing import Dict, Tuple, List
from typing_extensions import Final
from collections import defaultdict

logger: Logger = logging.getLogger("PolyProcess")

"""
This "Final" type means this is just a const
The 8 comes from two uint32_t's representing a nodes parents
"""
taint_node_size: Final[int] = 8


@dataclass
class SourceMetadata:
    taint_range_start: int
    taint_range_end: int


class PolyProcess:
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
        self.processed_taint_sets: Dict[str, Dict[str, Dict[str, List[int]]]] = {}
        self.taint_sets = self.polytracker_json["tainted_functions"]
        self.forest_file = open(polytracker_forest_path, "rb")
        self.forest_file_size = os.path.getsize(polytracker_forest_path)
        self.taint_forest: nx.DiGraph = nx.DiGraph()
        self.source_metadata: Dict[str, SourceMetadata] = {}
        self.canonical_mapping: Dict[int, Tuple[str, int]] = {}
        self.process_source_metadata()
        self.process_canonical_mapping()
        self.process_forest()
        self.outfile = "polytracker.json"

    def process_source_metadata(self):
        source_info = self.polytracker_json["taint_sources"]
        source_prog_bar = tqdm(source_info)
        source_prog_bar.set_description("Processing source metadata")
        for source in source_prog_bar:
            self.source_metadata[source] = SourceMetadata(source_info[source]["start_byte"], source_info[source]["end_byte"])

    def process_canonical_mapping(self):
        canonical_map = self.polytracker_json["canonical_mapping"]
        source_prog_bar = tqdm(canonical_map)
        source_prog_bar.set_description("Processing canonical mapping")
        for source in source_prog_bar:
            for label_offset_pair in canonical_map[source]:
                self.canonical_mapping[label_offset_pair[0]] = (source, label_offset_pair[1])

    def set_output_filepath(self, filepath: str):
        self.outfile = filepath

    def validate_forest(self) -> bool:
        return self.forest_file_size % taint_node_size == 0

    def max_node(self) -> int:
        return self.forest_file_size // taint_node_size

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
        is_valid = self.validate_forest()
        if not is_valid:
            raise Exception("Invalid taint forest!")
        nodes_to_process = tqdm(range(self.max_node()))
        nodes_to_process.set_description("Processing taint forest")
        for curr_node in nodes_to_process:
            taint_forest_entry = struct.unpack("=II", self.forest_file.read(taint_node_size))
            parent_1: int = taint_forest_entry[0]
            parent_2: int = taint_forest_entry[1]
            self.taint_forest.add_node(curr_node)
            # Parents for canonical labels should have parents of label 0
            assert parent_1 == parent_2 == 0 or (parent_1 != 0 and parent_2 != 0)
            if parent_1 != 0 and parent_2 != 0:
                self.taint_forest.add_edge(curr_node, parent_1)
                self.taint_forest.add_edge(curr_node, parent_2)

    def draw_forest(self):
        logger.log(logging.DEBUG, "Drawing forest")
        pos = nx.nx_agraph.graphviz_layout(self.taint_forest)
        nx.draw(self.taint_forest, pos=pos)
        write_dot(self.taint_forest, "taint_forest.dot")
        check_call(["dot", "-Tpdf", "taint_forest.dot", "-o", "taint_forest.pdf"])

    def is_canonical_label(self, label: int) -> bool:
        try:
            out_edges = self.taint_forest.edges(label)
            if len(out_edges) == 0:
                return True
        except nx.exception.NetworkXError:
            raise
        return False

    def get_canonical_offset(self, label: int) -> int:
        return self.canonical_mapping[label][1]

    def get_canonical_source(self, label: int) -> str:
        return self.canonical_mapping[label][0]

    def process_taint_sets(self):
        taint_sets = tqdm(self.taint_sets)
        processed_labels = defaultdict(lambda: defaultdict(lambda: defaultdict(set)))
        for function in taint_sets:
            taint_sets.set_description(f"Processing {function}")
            label_list = self.taint_sets[function]["input_bytes"]
            # Function --> Input_bytes/Cmp bytes --> Source --> labels
            for label in label_list:
                # Canonical labels
                canonical_labels = set(
                    label for label in nx.dfs_preorder_nodes(self.taint_forest, label) if self.is_canonical_label(label)
                )
                # Now partition based on taint source
                for can_label in canonical_labels:
                    offset = self.get_canonical_offset(can_label)
                    source = self.get_canonical_source(can_label)
                    processed_labels[function]["input_bytes"][source].add(offset)
                    # Check if this function has cmp bytes/if we should add the label
                    if "cmp_bytes" in self.taint_sets[function]:
                        if label in self.taint_sets[function]["cmp_bytes"]:
                            processed_labels[function]["cmp_bytes"][source].add(offset)

            # Now that we have constructed the input_bytes sources, convert it to a sorted list:
            for source in processed_labels[function]["input_bytes"]:
                processed_labels[function]["input_bytes"][source] = list(
                    sorted(processed_labels[function]["input_bytes"][source])
                )
                processed_labels[function]["cmp_bytes"][source] = list(sorted(processed_labels[function]["cmp_bytes"][source]))
        self.processed_taint_sets = processed_labels

    def output_processed_json(self):
        # Remove canonical mapping
        processed_json = defaultdict(dict)
        processed_json["tainted_functions"] = self.processed_taint_sets
        processed_json["runtime_cfg"] = self.polytracker_json["runtime_cfg"]
        processed_json["version"] = self.polytracker_json["version"]
        processed_json["taint_sources"] = self.polytracker_json["taint_sources"]
        processed_json["tainted_input_blocks"] = self.polytracker_json["tainted_input_blocks"]
        with open(self.outfile, "w") as out_fd:
            json.dump(processed_json, out_fd, indent=4)
