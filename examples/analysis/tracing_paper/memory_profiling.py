#!/usr/bin/env python3

from analysis import Analysis, CFLog
from argparse import ArgumentParser
from functools import partialmethod
from json import load
from os import environ
from pathlib import Path
from polytracker import PolyTrackerTrace
from tqdm import tqdm
import tracemalloc

# tqdm can be noisy and we want profiler output
environ["TQDM_DISABLE"] = "1"
tqdm.__init__ = partialmethod(tqdm.__init__, disable=True)

parser = ArgumentParser(
    prog="memory_profiling.py",
    description="memory profiling for TDAG analysis"
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
    help="Path to functionid.json function trace for TDAG A (created by"
    " polytracker's cflog pass)",
    required=True,
)
parser.add_argument(
    "-tb",
    "--tdag_b",
    type=Path,
    help="Path to the second TDAG (B) trace to compare (created by "
    "polytracker's cflog pass)",
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
trace_a = PolyTrackerTrace.load(args.tdag_a, taint_forest=False)
with open(args.function_id_json_a) as json_file:
    json_a = load(json_file)
trace_b = PolyTrackerTrace.load(args.tdag_b, taint_forest=False)
with open(args.function_id_json_b) as json_file:
    json_b = load(json_file)
cflog_a: CFLog = analysis.get_cflog(trace_a.tdfile, json_a)
cflog_b: CFLog = analysis.get_cflog(trace_b.tdfile, json_b)
snapshot2 = tracemalloc.take_snapshot()

print(" [ loading two cflogs comparison : tracemalloc ] ")
for stat in snapshot2.compare_to(snapshot1, "lineno")[:10]:
    print(stat)

snapshot3 = tracemalloc.take_snapshot()
diff = tuple(analysis.get_lookahead_only_diff_entries(cflog_a, cflog_b))
snapshot4 = tracemalloc.take_snapshot()
print("[ lookahead-only diff : tracemalloc ]")
for stat in snapshot4.compare_to(snapshot3, "lineno")[:10]:
    print(stat)

snapshot5 = tracemalloc.take_snapshot()
diff = tuple(analysis.get_differential_entries(cflog_a, cflog_b))
snapshot6 = tracemalloc.take_snapshot()
print("[ lookahead-only versus graphtage diff : tracemalloc ]")
for stat in snapshot6.compare_to(snapshot5, "lineno")[:10]:
    print(stat)
