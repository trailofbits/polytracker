import argparse
from dataclasses import dataclass
from logging import Logger
from tqdm import tqdm
import logging
import os
import multiprocessing
import networkx as nx
import json
import sys
import matplotlib.pyplot as plt
from networkx.drawing.nx_pydot import write_dot
from typing import List, Set
from typing import Dict

logger: Logger = logging.getLogger("PolyProcess")

# TODO Version trick Evan showed me
"""
This "Final" type means this is just a const 13
Final is in python 3.8, currently this is 3.7
This 13 is the size (bytes) of the taint node struct defined in dfsan_types.h
"""
taint_node_size: int = 13



@dataclass
class TaintMetadata:
    decay_val: int
    taint_source: int

@dataclass
class SourceMetadata:
    taint_range_start: int
    taint_range_end: int


"""
This is the PolyProcess class

This class takes two arguments

1. PolyTracker produced json containing CFG, taint sets, and version number. (PolyMerge has better version parsing)

2. PolyTracker raw taint forest

PolyProcess will take these files and: 

1. Reconstruct the CFG, taint forest and taint sets 

2. Process the taint sets to produce a final json containing the byte offsets touched in each function   
"""


class PolyProcess:
    def __init__(self, polytracker_json_path: str, polytracker_forest_path: str):
        if not os.path.exists(polytracker_json_path):
            print("Error! Could not find polytracker json path")
        if not os.path.exists(polytracker_forest_path):
            print("Error! Could not find polytracker forest path")

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
        self.outfile = "PolyTracker.json"

    """
    This function reads the taint forest file and converts it to a networkX graph
    
    The taint forest file is a bunch of raw bytes, where each sizeof(dfsan_label) chunk 
    represents a taint_node struct. The actual definition of the struct can be found in 
    include/dfsan_types.h 
    
    The function that produces this taint forest is outputRawTaintForest
    
    Note that the taint info here (and anything of type label) is 1 indexed, because 0 is the null index. 
    
    The way we convert back to canonical bytes is by travelling up the forest to a node with two null parents
    Then subtract one from that label, which gets you the original offset. 
    """

    def process_forest(self):
        logger.log(logging.DEBUG, "Processing taint forest!")
        num_taint_nodes: int = self.forest_file_size // taint_node_size
        print(f"Size is {self.forest_file_size} bytes, resulting in {num_taint_nodes} nodes")
        # Add the null node
        self.taint_forest.add_node(0)
        self.taint_metadata[0] = TaintMetadata(0, 0)

        # Read the taint header
        num_taint_sources = int.from_bytes(self.forest_file.read(4), "little")
        assert (self.forest_file_size - 4 - (num_taint_sources * 9)) % taint_node_size == 0

        print(f"num taint sources {num_taint_sources}")
        for i in range(num_taint_sources):
            # TODO struct unpack
            taint_source_id: int = int.from_bytes(self.forest_file.read(1), "little")
            taint_source_start: int = int.from_bytes(self.forest_file.read(4), "little")
            taint_source_end: int = int.from_bytes(self.forest_file.read(4), "little")
            print(f"id: {taint_source_id}, start: {taint_source_start}, end: {taint_source_end}")
            self.source_metadata[taint_source_id] = SourceMetadata(taint_source_start, taint_source_end)

        curr_node = 0
        while curr_node < num_taint_nodes:
            # TODO Struct unpack
            parent_1: int = int.from_bytes(self.forest_file.read(4), "little")
            parent_2: int = int.from_bytes(self.forest_file.read(4), "little")
            taint_source = int.from_bytes(self.forest_file.read(1), "little")
            decay: int = int.from_bytes(self.forest_file.read(4), "little")
            self.taint_forest.add_node(curr_node + 1)
            # Parents for canonical labels should have parents of label 0
            self.taint_metadata[curr_node + 1] = TaintMetadata(decay, taint_source)
            if parent_1 != 0 and parent_2 != 0:
                self.taint_forest.add_edge(curr_node + 1, parent_1)
                self.taint_forest.add_edge(curr_node + 1, parent_2)
            curr_node += 1

    # TODO Convert to PDF
    def draw_forest(self):
        logger.log(logging.DEBUG, "Drawing forest")
        pos = nx.nx_agraph.graphviz_layout(self.taint_forest)
        nx.draw(self.taint_forest, pos=pos)
        write_dot(self.taint_forest, "taint_forest.dot")

    def is_canonical(self, label):
        # Taint source id
        id = self.taint_metadata[label].taint_source
        # Taint range
        source_data = self.source_metadata[id]
        return source_data.taint_range_start <= (label - 1) <= source_data.taint_range_end

    # TODO Traversal
    # TODO memoize
    # TODO parallelize
    def process_taint_sets(self):
        # print(self.polytracker_json)
        # print(self.polytracker_json.keys())
        taint_sets = tqdm(self.taint_sets)
        processed_sets = {}
        for function in taint_sets:
            taint_sets.set_description(f"Processing {function}")
            # Typically only one source atm.
            for source in self.taint_sets[function]["input_bytes"]:
                label_set: List[int] = self.taint_sets[function]["input_bytes"][source]
                processed_sets[function] = {"input_bytes": {source : list()}}
                for label in label_set:
                    #preds = nx.dfs_successors(self.taint_forest, label)
                    preds = list(nx.dfs_preorder_nodes(self.taint_forest, label, 1000000))
                    # Converts to canonical bytes
                    if len(preds) == 0:
                        processed_sets[function]["input_bytes"][source] += (label - 1)
                    else:
                        #preds = preds[label]
                        test_list = list(filter(self.is_canonical, preds))
                        #print(list(test))
                        assert len(test_list) > 0
                        test_list = list(map(lambda x: x - 1, test_list))
                        processed_sets[function]["input_bytes"][source] += test_list
                        processed_sets[function]["input_bytes"][source] = list(set(processed_sets[function]["input_bytes"][source]))

        self.polytracker_json["tainted_functions"] = processed_sets
        output_json = json.dumps(self.polytracker_json, indent=4)
        out_fd = open(self.outfile, "w")
        out_fd.write(output_json)
        out_fd.close()


def main():
    parser = argparse.ArgumentParser(description='''
    A utility to process the JSON and raw output of 'polytracker' with a 
    polytracker.json and a polytracker_forest.bin 
    ''')
    parser.add_argument("--json", "-j", type=str, default=None, help="Path to polytracker json file")
    parser.add_argument("--forest", "-f", type=str, default=None, help="Path to the polytracker forest bin")
    parser.add_argument("--debug", "-d", action='store_true', default=None, help="Enables debug logging")
    parser.add_argument("--draw-forest", action='store_true', default=None, help="Produces a taint forest dot file")
    parser.add_argument("--outfile", type=str, default=None, help="Specify outfile JSON path/name")

    args = parser.parse_args(sys.argv[1:])

    if args.debug:
        logger.setLevel(logging.DEBUG)

    draw_forest = args.draw_forest is not None

    if args.json is None:
        print("Error: Path to JSON not specified")
        return
    if args.forest is None:
        print("Error: Path to forest bin not specified")
        return

    polyprocess = PolyProcess(args.json, args.forest)
    # Output the processed json
    polyprocess.process_taint_sets()
    # Output optional taint forest diagram
    if draw_forest:
        polyprocess.draw_forest()


main()
