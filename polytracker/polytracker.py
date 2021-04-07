import logging
import pkg_resources

from .tracing import *

log = logging.getLogger("PolyTracker")

VersionElement = Union[int, str]


def version() -> str:
    return pkg_resources.require("polytracker")[0].version


# class TaintForestCommand(Command):
#     name = "forest"
#     help = "commands related to the taint forest"
#     parser: ArgumentParser
#
#     def __init_arguments__(self, parser: ArgumentParser):
#         self.parser = parser
#
#     def run(self, args: Namespace):
#         self.parser.print_help()
#
#
# class DrawTaintForestCommand(Subcommand[TaintForestCommand]):
#     name = "draw"
#     help = "render the taint forest to a Graphviz .dot file"
#     parent_type = TaintForestCommand
#
#     def __init_arguments__(self, parser):
#         parser.add_argument(
#             "taint_forest_bin", type=str, help="the taint forest file for the trace"
#         )
#         parser.add_argument(
#             "output_dot_path", type=str, help="the path to which to save the .dot graph"
#         )
#
#     def run(self, args: Namespace):
#         forest = TaintForest(args.taint_forest_bin)
#         forest.to_graph().to_dot().save(args.output_dot_path)
