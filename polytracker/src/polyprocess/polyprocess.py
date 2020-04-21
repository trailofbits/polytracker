import argparse
from dataclasses import dataclass
import tqdm
import os
import multiprocessing
import networkx as nx
import json


@dataclass
class TaintMetadata:
    decay_val: int
    taint_source: int


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
        self.polytracker_json = json.loads(self.json_file)

        self.forest_file = open(polytracker_forest_path, "rb")
        self.forest_file_size = os.path.getsize(polytracker_forest_path)
        # Actual taint forest which is just a graph of
        self.taint_forest = nx.Graph()
        self.taint_metadata: dict = {}
        self.process_forest()

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
        num_taint_nodes = self.forest_file_size / 13
        print(f"Size is {self.forest_file_size} bytes, resulting in {num_taint_nodes} nodes")
        assert self.forest_file_size % 13 == 0
        # Add the null node
        self.taint_forest.add_node(0)
        self.taint_metadata[0] = TaintMetadata(0, 0)
        curr_node = 0
        while curr_node < num_taint_nodes:
            parent_1: int = int(self.forest_file.read(4))
            parent_2: int = int(self.forest_file.read(4))
            taint_source = int(self.forest_file.read(1))
            decay: int = int(self.forest_file.read(4))
            self.taint_forest.add_node(curr_node + 1)
            # Parents for canonical labels should have parents of label 0
            self.taint_forest.add_edge(curr_node + 1, parent_1)
            self.taint_forest.add_edge(curr_node + 1, parent_2)
            self.taint_metadata[curr_node + 1] = TaintMetadata(decay, taint_source)
            curr_node += 1
        nx.draw(self.taint_forest)