import json

from typing import Dict, List, TextIO

from .mimid.treeminer import miner


def parse_polytracker_trace(trace_file: TextIO) -> List[Dict]:
    try:
        data = json.load(trace_file)
    except json.decoder.JSONDecodeError as de:
        raise ValueError(f"Error parsing PolyTracker JSON file {trace_file.name}", de)
    if 'trace' not in data:
        raise ValueError(f"File {trace_file.name} was not recorded with POLYTRACE=1!")
    return data['trace']


def extract(traces: List[Dict]):
    return miner(traces)
