#!/usr/bin/env python3

from analysis import Analysis, CFLog, CFLogEntry
from argparse import ArgumentParser
from functools import partialmethod
from json import load
from os import environ
from pathlib import Path
from polytracker import PolyTrackerTrace, TDProgramTrace
from tqdm import tqdm
import tracemalloc
from typing import Iterable

# tqdm can be noisy and we want profiler output
environ["TQDM_DISABLE"] = "1"
tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)

parser = ArgumentParser(
    prog="memory_profiling.py", description="memory profiling for TDAG analysis"
)
parser.add_argument(
    "-ta",
    "--tdag_a",
    type=Path,
    help="Path to the first TDAG trace (A) to analyse",
    required=True,
)
parser.add_argument(
    "-fa",
    "--function_id_json_a",
    type=Path,
    help="Path to functionid.json function trace for TDAG A (created by polytracker's cflog pass)",
    required=True,
)
parser.add_argument(
    "-tb",
    "--tdag_b",
    type=Path,
    help="Path to the second TDAG (B) trace to compare (created by polytracker's cflog pass)",
    required=True,
)
parser.add_argument(
    "-fb",
    "--function_id_json_b",
    type=Path,
    help="Path to functionid.json function trace for TDAG B",
    required=True,
)
args = parser.parse_args()

tracemalloc.start()
analysis = Analysis()

snapshot1 = tracemalloc.take_snapshot()
trace1 = PolyTrackerTrace.load(args.tdag_a)
snapshot2 = tracemalloc.take_snapshot()
print("[ PolyTrackerTrace.load() [1] : tracemalloc ]")
for stat in snapshot2.compare_to(snapshot1, "lineno")[:20]:
    print(stat)

with open(args.function_id_json_a) as json_file:
    json_1 = load(json_file)

snapshot3 = tracemalloc.take_snapshot()
trace2 = PolyTrackerTrace.load(args.tdag_b)
snapshot4 = tracemalloc.take_snapshot()
print("[ PolyTrackerTrace.load() [2] : tracemalloc ]")
for stat in snapshot4.compare_to(snapshot3, "lineno")[:20]:
    print(stat)

print(" [ trace loading memory usage comparison : tracemalloc ] ")
for stat in snapshot4.compare_to(snapshot2, "lineno")[:20]:
    print(stat)

with open(args.function_id_json_b) as json_file:
    json_2 = load(json_file)

snapshot5 = tracemalloc.take_snapshot()
cflog_entries: Iterable[CFLogEntry] = analysis._get_cflog_entries(trace1.tdfile, json_1)
snapshot6 = tracemalloc.take_snapshot()

print(" [ cflog entry building _get_cflog_entries() : tracemalloc ] ")
for stat in snapshot6.compare_to(snapshot5, "lineno")[:20]:
    print(stat)

cflog: CFLog = analysis.get_cflog(trace1.tdfile, json_1)
snapshot7 = tracemalloc.take_snapshot()

print(" [ _get_cflog_entries() versus get_cflog() : tracemalloc ] ")
for stat in snapshot7.compare_to(snapshot6, "lineno")[:20]:
    print(stat)
