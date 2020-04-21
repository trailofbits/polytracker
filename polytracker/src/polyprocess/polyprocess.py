import argparse
import tqdm
import os
import multiprocessing
import networkx as nx
import json

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

        self.forest_file = open(polytracker_forest_path, "r")
        #TODO NetworkX reconstruct graph
