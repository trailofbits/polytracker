import json
import logging
import os
from argparse import ArgumentParser, Namespace
from collections import defaultdict
from io import StringIO
import pkg_resources
from typing import (
    Any,
    Callable,
    FrozenSet,
    Iterator,
    KeysView,
    TextIO,
    Tuple,
)

from intervaltree import Interval, IntervalTree

from .cfg import CFG, FunctionInfo
from .plugins import Command, Subcommand
from .taint_forest import TaintForest
from .tracing import *
from .visualizations import file_diff, Image, temporal_animation

log = logging.getLogger("PolyTracker")

VersionElement = Union[int, str]


def version() -> str:
    return pkg_resources.require("polytracker")[0].version


class TemporalVisualization(Command):
    name = "temporal"
    help = "generate an animation of the file accesses in a runtime trace"

    def __init_arguments__(self, parser):
        parser.add_argument(
            "polytracker_json", type=str, help="the JSON file for the trace"
        )
        parser.add_argument(
            "taint_forest_bin", type=str, help="the taint forest file for the trace"
        )
        parser.add_argument(
            "OUTPUT_GIF_PATH", type=str, help="the path to which to save the animation"
        )

    def run(self, args):
        with open(args.polytracker_json, "r") as f:
            polytracker_json_obj = json.load(f)
        sources = polytracker_json_obj["canonical_mapping"].keys()
        if len(sources) != 1:
            raise ValueError(
                f"Expected only a single taint source, but found {sources}"
            )
        source = next(iter(sources))
        canonical_mapping = dict(polytracker_json_obj["canonical_mapping"][source])
        del polytracker_json_obj
        forest = TaintForest(args.taint_forest_bin, canonical_mapping=canonical_mapping)
        temporal_animation(args.OUTPUT_GIF_PATH, forest)


class TaintForestCommand(Command):
    name = "forest"
    help = "commands related to the taint forest"
    parser: ArgumentParser

    def __init_arguments__(self, parser: ArgumentParser):
        self.parser = parser

    def run(self, args: Namespace):
        self.parser.print_help()


class DrawTaintForestCommand(Subcommand[TaintForestCommand]):
    name = "draw"
    help = "render the taint forest to a Graphviz .dot file"
    parent_type = TaintForestCommand

    def __init_arguments__(self, parser):
        parser.add_argument(
            "taint_forest_bin", type=str, help="the taint forest file for the trace"
        )
        parser.add_argument(
            "output_dot_path", type=str, help="the path to which to save the .dot graph"
        )

    def run(self, args: Namespace):
        forest = TaintForest(args.taint_forest_bin)
        forest.to_graph().to_dot().save(args.output_dot_path)
