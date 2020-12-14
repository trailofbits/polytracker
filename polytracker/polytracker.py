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
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    KeysView,
    List,
    Optional,
    Set,
    TextIO,
    Tuple,
    Union,
)

from intervaltree import Interval, IntervalTree
from tqdm import tqdm
import sqlite3

from .cfg import CFG, FunctionInfo
from .plugins import Command, Subcommand
from .taint_forest import TaintForest
from .visualizations import file_diff, Image, temporal_animation

log = logging.getLogger("PolyTracker")

VersionElement = Union[int, str]


def version() -> str:
    return pkg_resources.require("polytracker")[0].version


class ProgramTrace:
    def __init__(self, version: Tuple[VersionElement, ...], function_data: Iterable[FunctionInfo]):
        self.polytracker_version: Tuple[VersionElement, ...] = version
        self.functions: Dict[str, FunctionInfo] = {f.name: f for f in function_data}
        self._cfg: Optional[CFG] = None
        self._taint_sources: Optional[FrozenSet[str]] = None

    @property
    def taint_sources(self) -> FrozenSet[str]:
        if self._taint_sources is None:
            self._taint_sources = frozenset([s for func in self.functions.values() for s in func.taint_sources])
        return self._taint_sources

    def source_size(self, source: str) -> int:
        first_function = next(iter(self.functions.values()))
        if os.path.exists(source) or (
                len(self.taint_sources) == 1 and isinstance(first_function, TaintForestFunctionInfo)):
            return first_function.source_size(source)
        else:
            return max(func.source_size(source) for func in self.functions.values())

    def taint_source_sizes(self) -> Dict[str, int]:
        return {source: self.source_size(source) for source in self.taint_sources}

    @property
    def cfg(self) -> CFG:
        if self._cfg is not None:
            return self._cfg
        self._cfg = CFG()
        self._cfg.add_nodes_from(self.functions.values())
        for f in list(self.functions.values()):
            for caller in f.called_from:
                if caller not in self.functions:
                    info = FunctionInfo(caller, {})
                    self.functions[caller] = info
                    self._cfg.add_node(info)
                    self._cfg.add_edge(info, f)
                else:
                    self._cfg.add_edge(self.functions[caller], f)
        return self._cfg

    def diff(self, trace: "ProgramTrace") -> "TraceDiff":
        return TraceDiff(self, trace)

    def __repr__(self):
        return f"{self.__class__.__name__}(polytracker_version={self.polytracker_version!r}, function_data={list(self.functions.values())!r})"

    def __str__(self):
        if len(self.taint_sources) == 0:
            return repr(self)
        elif len(self.taint_sources) == 1:
            return next(iter(self.taint_sources))
        else:
            return f"{{{', '.join(self.taint_sources)}}}"


def print_file_context(
        output: TextIO, path: str, offset: int, length: int, num_bytes_context: int = 32, max_highlight_bytes=32,
        indent: str = ""
):
    if length > max_highlight_bytes:
        extra_bytes = length - max_highlight_bytes
        length = max_highlight_bytes
    else:
        extra_bytes = 0
    extra_context_bytes = num_bytes_context
    extra_context_before = extra_context_bytes // 2
    if extra_bytes > 0:
        extra_context_bytes = extra_context_before
    if offset - extra_context_before < 0:
        extra_context_before = offset
    start = offset - extra_context_before
    output.write(f"{indent}@{offset}\n{indent}")
    with open(path, "rb") as s:
        s.seek(start)
        data = s.read(length + extra_context_bytes)
        highlight_start = -1
        highlight_length = -1
        written = 0
        for i, b in enumerate(data):
            if b == ord("\n"):
                to_write = "\\n"
            elif b == ord("\r"):
                to_write = "\\r"
            elif b == ord("\\"):
                to_write = "\\\\"
            elif b == ord("\t"):
                to_write = "\\t"
            elif ord(" ") <= b <= ord("~"):
                to_write = chr(b)
            else:
                to_write = f"\\x{b:02x}"
            if i == extra_context_before:
                highlight_start = written
            if i == extra_context_before + length:
                highlight_length = written - highlight_start
            written += len(to_write)
            output.write(to_write)
        if extra_bytes:
            output.write(f" [ … plus {extra_bytes} additional byte{['', 's'][extra_bytes > 1]} … ]")
        output.write("\n")
        if highlight_length < 0 <= highlight_start:
            highlight_length = written - highlight_start
        if highlight_length > 0:
            output.write(f"{indent}{' ' * highlight_start}{'^' * highlight_length}\n")


class ControlFlowDiff:
    def __init__(self, trace1: ProgramTrace, trace2: ProgramTrace, function_name: str):
        self.trace1: ProgramTrace = trace1
        self.trace2: ProgramTrace = trace2
        self.func: str = function_name
        self._first_function_with_different_control_flow: Optional[str] = None
        self._diffed: bool = False

    @property
    def first_function_with_different_control_flow(self) -> Optional[str]:
        if not self._diffed:
            self._diff()
        return self._first_function_with_different_control_flow

    def _diff(self):
        if self._diffed:
            return
        self._diffed = True
        if self.func not in self.trace1.functions or self.func not in self.trace2.functions:
            return
        func1 = self.trace1.functions[self.func]
        func2 = self.trace2.functions[self.func]
        doms1 = self.trace1.cfg.dominator_forest
        doms2 = self.trace2.cfg.dominator_forest

        ancestors1 = doms1.ancestors(func1)
        ancestors2 = doms2.ancestors(func2)

        ancestors1 &= ancestors2
        ancestors2 &= ancestors1

        if not ancestors1 or not ancestors2:
            # they have no ancestors in common
            return

        for a1, a2 in zip(ancestors1, ancestors2):
            if a1.name != a2.name:
                continue
            if a1.cmp_bytes != a2.cmp_bytes:
                self._first_function_with_different_control_flow = a1.name
                break

    def __bool__(self):
        return self.first_function_with_different_control_flow is not None


class FunctionDiff:
    def __init__(self, func1: FunctionInfo, func2: FunctionInfo):
        assert func1.name == func2.name
        self.func1: FunctionInfo = func1
        self.func2: FunctionInfo = func2
        self._cmp_bytes_only_in_first: Optional[Dict[str, Set[int]]] = None
        self._cmp_bytes_only_in_second: Optional[Dict[str, Set[int]]] = None

    @property
    def cmp_bytes_only_in_first(self) -> Dict[str, Set[int]]:
        if self._cmp_bytes_only_in_first is None:
            self._diff()
        return self._cmp_bytes_only_in_first  # type: ignore

    @property
    def cmp_bytes_only_in_second(self) -> Dict[str, Set[int]]:
        if self._cmp_bytes_only_in_second is None:
            self._diff()
        return self._cmp_bytes_only_in_second  # type: ignore

    def cmp_chunks_only_in_first(self) -> Iterator[Tuple[str, Tuple[int, int]]]:
        for source, byte_offsets in self.cmp_bytes_only_in_first.items():
            for start, end in FunctionInfo.tainted_chunks(byte_offsets):
                yield source, (start, end)

    def cmp_chunks_only_in_second(self) -> Iterator[Tuple[str, Tuple[int, int]]]:
        for source, byte_offsets in self.cmp_bytes_only_in_second.items():
            for start, end in FunctionInfo.tainted_chunks(byte_offsets):
                yield source, (start, end)

    def __hash__(self):
        return hash((self.func1, self.func2))

    def __eq__(self, other):
        return isinstance(other, FunctionDiff) and other.func1 == self.func1 and other.func2 == self.func2

    def __ne__(self, other):
        return not (self == other)

    def _diff(self):
        if self._cmp_bytes_only_in_first is None:
            shared_sources = self.func1.cmp_bytes.keys() & self.func2.cmp_bytes.keys()
            self._cmp_bytes_only_in_first = {
                source: set(cmp) for source, cmp in self.func1.cmp_bytes.items() if source not in shared_sources
            }
            self._cmp_bytes_only_in_second = {
                source: set(cmp) for source, cmp in self.func2.cmp_bytes.items() if source not in shared_sources
            }
            for shared_source in shared_sources:
                in_first = set(self.func1.cmp_bytes[shared_source])
                in_second = set(self.func1.cmp_bytes[shared_source])
                only_in_first = in_first - in_second
                if only_in_first:
                    self._cmp_bytes_only_in_first[shared_source] = only_in_first
                only_in_second = in_second - in_first
                if only_in_second:
                    self._cmp_bytes_only_in_second[shared_source] = only_in_second

    def __bool__(self):
        return bool(self.cmp_bytes_only_in_first) or bool(self.cmp_bytes_only_in_second)


class TraceDiff:
    def __init__(self, trace1: ProgramTrace, trace2: ProgramTrace):
        self.trace1: ProgramTrace = trace1
        self.trace2: ProgramTrace = trace2
        self._functions_only_in_first: Optional[FrozenSet[FunctionInfo]] = None
        self._functions_only_in_second: Optional[FrozenSet[FunctionInfo]] = None
        self._bytes_only_in_first: Optional[Dict[str, IntervalTree]] = None
        self._bytes_only_in_second: Optional[Dict[str, IntervalTree]] = None
        self._first_intervals: Dict[str, IntervalTree] = defaultdict(IntervalTree)
        self._second_intervals: Dict[str, IntervalTree] = defaultdict(IntervalTree)

    @property
    def first_intervals(self) -> Dict[str, IntervalTree]:
        self._diff_bytes()
        return self._first_intervals

    @property
    def second_intervals(self) -> Dict[str, IntervalTree]:
        self._diff_bytes()
        return self._second_intervals

    @property
    def functions_only_in_first(self) -> FrozenSet[FunctionInfo]:
        if self._functions_only_in_first is None:
            self._diff_functions()
        return self._functions_only_in_first  # type: ignore

    @property
    def functions_only_in_second(self) -> FrozenSet[FunctionInfo]:
        if self._functions_only_in_second is None:
            self._diff_functions()
        return self._functions_only_in_second  # type: ignore

    @property
    def functions_in_both(self) -> Iterator[FunctionDiff]:
        for fname in {
            name
            for name in self.trace1.functions.keys()
            if name not in {f.name for f in (self.functions_only_in_first | self.functions_only_in_second)}
        }:
            yield FunctionDiff(self.trace1.functions[fname], self.trace2.functions[fname])

    def _diff_functions(self):
        if self._functions_only_in_first is None:
            first_funcs = frozenset(self.trace1.functions.values())
            second_funcs = frozenset(self.trace2.functions.values())
            self._functions_only_in_first = first_funcs - second_funcs
            self._functions_only_in_second = second_funcs - first_funcs

    def _diff_bytes(self):
        if self._bytes_only_in_first is not None:
            return
        # TODO: Instead of looking at what functions touched, just look at the bytes in the canonical mapping!
        with tqdm(desc="Diffing tainted byte regions", leave=False, unit=" trace", total=2) as t:
            for func in tqdm(self.trace1.functions.values(), desc="Trace 1", unit=" functions", leave=False):
                for source, (start, end) in func.input_chunks():
                    self._first_intervals[source].add(Interval(start, end))
            for interval in self._first_intervals.values():
                interval.merge_overlaps()
            t.update(1)
            for func in tqdm(self.trace2.functions.values(), desc="Trace 2", unit=" functions", leave=False):
                for source, (start, end) in func.input_chunks():
                    self._second_intervals[source].add(Interval(start, end))
            for interval in self._second_intervals.values():
                interval.merge_overlaps()
            t.update(2)
            self._bytes_only_in_first = {}
            self._bytes_only_in_second = {}
            for source in self._first_intervals.keys() & self._second_intervals.keys():
                # shared sources
                self._bytes_only_in_first[source] = self._first_intervals[source].copy()
                for interval in tqdm(
                        self._second_intervals[source], desc="Removing Trace 1 Overlap", unit=" intervals", leave=False
                ):
                    self._bytes_only_in_first[source].remove_overlap(interval.begin, interval.end)
                self._bytes_only_in_second[source] = self._second_intervals[source].copy()
                for interval in tqdm(
                        self._first_intervals[source], desc="Removing Trace 2 Overlap", unit=" intervals", leave=False
                ):
                    self._bytes_only_in_second[source].remove_overlap(interval.begin, interval.end)
                assert len(self._bytes_only_in_first[source] & self._bytes_only_in_second[source]) == 0
            for source in self._first_intervals.keys() - self._second_intervals.keys():
                # sources only in first
                self._bytes_only_in_first[source] = self._first_intervals[source]
            for source in self._second_intervals.keys() - self._first_intervals.keys():
                # sources only in second
                self._bytes_only_in_second[source] = self._second_intervals[source]

    @property
    def input_chunks_only_in_first(self) -> Iterator[Tuple[str, Tuple[int, int]]]:
        if self._bytes_only_in_first is None:
            self._diff_bytes()
        for source, tree in self._bytes_only_in_first.items():  # type: ignore
            for interval in sorted(tree):
                yield source, (interval.begin, interval.end)

    @property
    def input_chunks_only_in_second(self) -> Iterator[Tuple[str, Tuple[int, int]]]:
        if self._bytes_only_in_second is None:
            self._diff_bytes()
        for source, tree in self._bytes_only_in_second.items():  # type: ignore
            for interval in sorted(tree):
                yield source, (interval.begin, interval.end)

    @property
    def has_input_chunks_only_in_first(self) -> bool:
        if self._bytes_only_in_first is None:
            self._diff_bytes()
        return any(len(tree) > 0 for tree in self._bytes_only_in_first.values())  # type: ignore

    @property
    def has_input_chunks_only_in_second(self) -> bool:
        if self._bytes_only_in_second is None:
            self._diff_bytes()
        return any(len(tree) > 0 for tree in self._bytes_only_in_second.values())  # type: ignore

    def to_image(self) -> Image:
        self._diff_bytes()
        sources = self.trace1.taint_sources | self.trace2.taint_sources
        for source in sources:
            num_bytes = max(self.trace1.source_size(source), self.trace2.source_size(source))
            return file_diff(
                num_bytes,
                lambda offset: source in self._first_intervals and self._first_intervals[source].overlaps(offset),
                # type: ignore
                lambda offset: source in self._second_intervals and self._second_intervals[source].overlaps(offset),
                # type: ignore
            )

    def __bool__(self):
        return bool(self.functions_only_in_first) or bool(self.functions_only_in_second)

    def __str__(self):
        status = StringIO()

        def print_chunk_info(chunks: Iterable[Tuple[str, Tuple[int, int]]], indent: str = "\t"):
            for source, (start, end) in chunks:
                if os.path.exists(source):
                    print_file_context(status, path=source, offset=start, length=end - start, indent=indent)
                else:
                    status.write(f"\tTouched {end - start} bytes at offset {start}\n")

        if self.has_input_chunks_only_in_first:
            status.write(
                "The reference trace touched the following byte regions that were not touched by the diffed " "trace:\n"
            )
            # generate the CFG first, because that can add functions to the trace:
            _ = self.trace1.cfg
            for src, (st, en) in self.input_chunks_only_in_first:
                print_chunk_info(((src, (st, en)),))
                for func in self.trace1.functions.values():
                    if IntervalTree.from_tuples((s, e) for r, (s, e) in func.input_chunks() if r == src).overlaps(st,
                                                                                                                  en):
                        # find the control flows that could have caused the diff
                        cfd = ControlFlowDiff(self.trace1, self.trace2, func.name)
                        if cfd:
                            different_function = cfd.first_function_with_different_control_flow
                            function_diff = FunctionDiff(
                                self.trace1.functions[different_function], self.trace2.functions[different_function]
                            )
                            if not bool(function_diff):
                                continue
                            status.write(
                                f"\tFunction {function_diff.func1!s} could contain the control flow that led "
                                "to this differential\n"
                            )
                            if function_diff.cmp_bytes_only_in_first:
                                status.write(
                                    "\t\tHere are the bytes that affected control flow only in the reference " "trace:\n"
                                )
                                print_chunk_info(function_diff.cmp_chunks_only_in_first(), indent="\t\t\t")
                            if function_diff.cmp_bytes_only_in_first:
                                status.write(
                                    "\t\tHere are the bytes that affected control flow only in the differed " "trace:\n"
                                )
                                print_chunk_info(function_diff.cmp_chunks_only_in_second(), indent="\t\t\t")

        if self.has_input_chunks_only_in_second:
            status.write(
                "The diffed trace touched the following byte regions that were not touched by the reference " "trace:\n"
            )
            # generate the CFG first, because that can add functions to the trace:
            _ = self.trace2.cfg
            for src, (st, en) in self.input_chunks_only_in_second:
                print_chunk_info(((src, (st, en)),))
                for func in self.trace2.functions.values():
                    if IntervalTree.from_tuples((s, e) for r, (s, e) in func.input_chunks() if r == src).overlaps(st,
                                                                                                                  en):
                        # find the control flows that could have caused the diff
                        cfd = ControlFlowDiff(self.trace1, self.trace2, func.name)
                        if cfd:
                            different_function = cfd.first_function_with_different_control_flow
                            function_diff = FunctionDiff(
                                self.trace1.functions[different_function], self.trace2.functions[different_function]
                            )
                            if not bool(function_diff):
                                continue
                            status.write(
                                f"\tFunction {function_diff.func1!s} could contain the control flow that led "
                                "to this differential\n"
                            )
                            if function_diff.cmp_bytes_only_in_first:
                                status.write(
                                    "\t\tHere are the bytes that affected control flow only in the reference " "trace:\n"
                                )
                                print_chunk_info(function_diff.cmp_chunks_only_in_first(), indent="\t\t\t")
                            if function_diff.cmp_bytes_only_in_first:
                                status.write(
                                    "\t\tHere are the bytes that affected control flow only in the differed " "trace:\n"
                                )
                                print_chunk_info(function_diff.cmp_chunks_only_in_second(), indent="\t\t\t")

        if not self.has_input_chunks_only_in_first and not self.has_input_chunks_only_in_second:
            status.write("Both traces consumed the exact same input byte regions\n")

        for func in self.functions_only_in_first:
            status.write(f"Function {func!s} was called in the reference trace but not in the diffed trace\n")
            print_chunk_info(func.input_chunks())
        for func in self.functions_only_in_second:
            status.write(f"Function {func!s} was called in the diffed trace but not in the reference trace\n")
            print_chunk_info(func.input_chunks())
        for func in self.functions_in_both:
            if func:
                # different input bytes affected control flow
                if func.cmp_bytes_only_in_first:
                    status.write(
                        f"Function {func.func1!s} in the reference trace had the following bytes that tainted "
                        "control flow which did not affect control flow in the diffed trace:\n"
                    )
                    print_chunk_info(func.cmp_chunks_only_in_first())
                if func.cmp_bytes_only_in_second:
                    status.write(
                        f"Function {func.func2!s} in the diffed trace had the following bytes that tainted "
                        "control flow which did not affect control flow in the reference trace:\n"
                    )
                    print_chunk_info(func.cmp_chunks_only_in_second())

        if not self:
            status.write(f"Traces do not differ")
        return status.getvalue()


POLYTRACKER_JSON_FORMATS: List[Tuple[Tuple[str, ...], Callable[[dict], ProgramTrace]]] = []
POLYTRACKER_SQL_FORMATS: List[Tuple[Tuple[str, ...], Callable[[dict], ProgramTrace]]] = []


def normalize_version(*version: Iterable[VersionElement]) -> Tuple[Any, ...]:
    version = tuple(str(v) for v in version)
    version = tuple(version) + ("0",) * (3 - len(version))
    version = tuple(version) + ("",) * (4 - len(version))
    return version


def polytracker_version(*version):
    def wrapper(func):
        POLYTRACKER_JSON_FORMATS.append((normalize_version(*version), func))
        POLYTRACKER_JSON_FORMATS.sort(reverse=True)
        return func

    return wrapper


def polytracker_sql_version(*version):
    def wrapper(func):
        POLYTRACKER_SQL_FORMATS.append((normalize_version(*version), func))
        POLYTRACKER_SQL_FORMATS.sort(reverse=True)
        return func

    return wrapper


def parse_sql(conn: sqlite3.Connection, input_id: int) -> ProgramTrace:
    version_query = "SELECT value FROM polytracker WHERE key='version';"
    cursor = conn.execute(version_query)
    print(cursor)
    # There should only be one row,
    items = [row for row in cursor]
    version_str: str = items[0][0]
    print(version_str)
    version = normalize_version(version_str.split("."))
    if len(version) > 4:
        log.warning(f"Unexpectedly long PolyTracker version: {version!r}")
    for i, (known_version, parser) in enumerate(POLYTRACKER_SQL_FORMATS):
        if version >= known_version:
            if i == 0 and version > known_version:
                log.warning(
                    f"PolyTracker version {version!r} "
                    "is newer than the latest supported by the polytracker Python module "
                    f"({'.'.join(known_version)})"
                )
        if version == known_version:
            return parser(conn, input_id)  # type: ignore
        raise ValueError(f"Unsupported PolyTracker version {version!r}")


@polytracker_sql_version(3, 1, 0, "")
def parse_db_v1(conn: sqlite3.Connection, input_id) -> ProgramTrace:
    # version = polytracker_json_obj["version"].split(".")
    version_query = "SELECT value FROM polytracker WHERE key='version';"
    cursor = conn.execute(version_query)
    print(cursor)
    version = [row for row in cursor]
    version_str = version[0][0]
    print(version_str)
    function_data = []
    tainted_functions = set()
    # To get tainted functions, this is the query I want to do, we can maybe use joins to optimize this query later
    # 1. Get the block_gid of every accessed label (taint label that was touched)
    # Distinct means no duplicates
    # block_gid_query = "SELECT DISTINCT block_gid FROM accessed_label WHERE input_id=?;"
    # results = conn.execute(block_gid_query, input_id)
    # 2. The high 32 bits of the block_gid correspond to the function index, so I suppose we apply the mask to each GID
    # This should just be integers, and im masking the higher bits.
    # function_ids = [row[0] & 0xFFFF0000 for row in results]

    # 3. Get the function names
    # results = conn.executemany("SELECT name FROM func WHERE id=?", function_ids)
    # tainted_functions = set(row[0] for row in results)
    # 3. add each element to the set tainted functions.
    # FIXME we need some document name
    # Execute the query here
    # FIXME Update the C++ side to respect access type again (input/cmp)
    # Get input bytes for all functions
    input_bytes_dict: Dict[int: Set[int]] = defaultdict(set)
    cmp_bytes_dict: Dict[int: Set[int]] = defaultdict(set)
    function_names: Dict[int: str] = {}
    called_from_dict: Dict[int: Set[int]] = defaultdict(set)

    func_name_results = conn.execute("SELECT name, id FROM func;")
    for row in func_name_results:
        # Each function should have a unique ID from instrumentation
        # Error out if thats not the case
        assert row[1] not in function_names
        function_names[row[1]] = row[0]

    runtime_cfg_results = conn.execute("SELECT callee, caller from func_cfg WHERE input_id=?", input_id)
    for row in runtime_cfg_results:
        called_from_dict[row[0]].add(row[1])

    input_bytes_results = conn.execute("SELECT block_gid, label FROM accessed_label WHERE input_id=? AND access_type=0",
                                       input_id)

    # Input bytes should be a superset of cmp bytes
    for row in input_bytes_results:
        input_bytes_dict[row[0] & 0xFFFF0000].add(row[1])
    cmp_bytes_results = conn.execute("SELECT block_gid, label FROM accessed_label WHERE input_id=? AND access_type=1",
                                     input_id)
    for row in cmp_bytes_results:
        cmp_byte_dicts[row[0] & 0xFFFF0000].add(row[1])

    # input_byte_pairs = [(row[0] & 0xFFFF0000, row[1]) for row in input_bytes_results]
    # cmp_byte_pairs = [(row[0] & 0xFFFF0000, row[1]) for row in cmp_bytes_results]
    # tainted_function_ids = set(row[0] & 0xFFFF0000 for row in input_bytes_results).union(
    #    cmp_row[0] & 0xFFFF0000 for cmp_row in cmp_bytes_results)

    # For every function that touched taint
    for tainted_func in input_bytes_dict:
        input_bytes = input_bytes_dict[tainted_func]
        if tainted_func in cmp_bytes_dict:
            cmp_bytes = cmp_bytes_dict[tainted_func]
        else:
            cmp_bytes = {}

    # Build up the runtime CFG, can build up a set/memoized dict the same way with tainted functions
    # 1. Query the func_cfg based on input_id and get all the runtime func calls
    # 2. Add function names to the runtime_cfg set.

    # Once all that is done, everything should work!
    for function_name, data in polytracker_json_obj["tainted_functions"].items():
        # This should be false??? im not sure lol. actually i like that this is true
        if "input_bytes" not in data:
            if "cmp_bytes" in data:
                input_bytes = data["cmp_bytes"]
            else:
                input_bytes = {}
        else:
            input_bytes = data["input_bytes"]
        if "cmp_bytes" in data:
            cmp_bytes = data["cmp_bytes"]
        else:
            cmp_bytes = input_bytes
        if function_name in polytracker_json_obj["runtime_cfg"]:
            called_from = frozenset(polytracker_json_obj["runtime_cfg"][function_name])
        else:
            called_from = frozenset()
        # Have this take a name, a list, a list, and a list.
        function_data.append(
            FunctionInfo(name=function_name, cmp_bytes=cmp_bytes, input_bytes=input_bytes, called_from=called_from)
        )
        tainted_functions.add(function_name)
    # Add any additional functions from the CFG that didn't operate on tainted bytes
    for function_name in polytracker_json_obj["runtime_cfg"].keys() - tainted_functions:
        function_data.append(
            FunctionInfo(name=function_name, cmp_bytes={},
                         called_from=polytracker_json_obj["runtime_cfg"][function_name])
        )
    return ProgramTrace(version=version, function_data=function_data)


def parse(polytracker_json_obj: dict, polytracker_forest_path: Optional[str] = None) -> ProgramTrace:
    if "version" in polytracker_json_obj:
        version = normalize_version(*polytracker_json_obj["version"].split("."))
        if len(version) > 4:
            log.warning(f"Unexpectedly long PolyTracker version: {polytracker_json_obj['version']!r}")
        for i, (known_version, parser) in enumerate(POLYTRACKER_JSON_FORMATS):
            # POLYTRACKER_JSON_FORMATS is auto-sorted in decreasing order
            if version >= known_version:
                if i == 0 and version > known_version:
                    log.warning(
                        f"PolyTracker version {polytracker_json_obj['version']!r} "
                        "is newer than the latest supported by the polytracker Python module "
                        f"({'.'.join(known_version)})"
                    )
                if int(known_version[0]) >= 2 and int(known_version[1]) > 0:
                    if polytracker_forest_path is None:
                        raise ValueError(
                            "A polytracker taint forest binary is required for version "
                            f"{'.'.join(map(str, known_version))} and above"
                        )
                    else:
                        return parser(polytracker_json_obj, polytracker_forest_path)  # type: ignore
        raise ValueError(f"Unsupported PolyTracker version {polytracker_json_obj['version']!r}")
    for function_name, function_data in polytracker_json_obj.items():
        if isinstance(function_data, dict) and "called_from" in function_data:
            # this is the second version of the output format
            return parse_format_v2(polytracker_json_obj)
        else:
            return parse_format_v1(polytracker_json_obj)
    return parse_format_v1(polytracker_json_obj)


@polytracker_version(0, 0, 1, "")
def parse_format_v1(polytracker_json_obj: dict) -> ProgramTrace:
    return ProgramTrace(
        version=(0, 0, 1),
        function_data=[
            FunctionInfo(function_name, {"": taint_bytes}) for function_name, taint_bytes in
            polytracker_json_obj.items()
        ],
    )


@polytracker_version(0, 0, 1, "alpha2.1")
def parse_format_v2(polytracker_json_obj: dict) -> ProgramTrace:
    function_data = []
    for function_name, data in polytracker_json_obj.items():
        if "input_bytes" not in data:
            if "cmp_bytes" in data:
                input_bytes = data["cmp_bytes"]
            else:
                input_bytes = {}
        else:
            input_bytes = data["input_bytes"]
        if "cmp_bytes" in data:
            cmp_bytes = data["cmp_bytes"]
        else:
            cmp_bytes = input_bytes
        if "called_from" in data:
            called_from = data["called_from"]
        else:
            called_from = ()
        function_data.append(
            FunctionInfo(name=function_name, cmp_bytes=cmp_bytes, input_bytes=input_bytes, called_from=called_from)
        )
    return ProgramTrace(version=(0, 0, 1, "alpha2.1"), function_data=function_data)


@polytracker_version(2, 0, 1)
@polytracker_version(2, 0, 0)
@polytracker_version(1, 0, 1)
def parse_format_v3(polytracker_json_obj: dict) -> ProgramTrace:
    version = polytracker_json_obj["version"].split(".")
    function_data = []
    tainted_functions = set()
    for function_name, data in polytracker_json_obj["tainted_functions"].items():
        if "input_bytes" not in data:
            if "cmp_bytes" in data:
                input_bytes = data["cmp_bytes"]
            else:
                input_bytes = {}
        else:
            input_bytes = data["input_bytes"]
        if "cmp_bytes" in data:
            cmp_bytes = data["cmp_bytes"]
        else:
            cmp_bytes = input_bytes
        if function_name in polytracker_json_obj["runtime_cfg"]:
            called_from = frozenset(polytracker_json_obj["runtime_cfg"][function_name])
        else:
            called_from = frozenset()
        function_data.append(
            FunctionInfo(name=function_name, cmp_bytes=cmp_bytes, input_bytes=input_bytes, called_from=called_from)
        )
        tainted_functions.add(function_name)
    # Add any additional functions from the CFG that didn't operate on tainted bytes
    for function_name in polytracker_json_obj["runtime_cfg"].keys() - tainted_functions:
        function_data.append(
            FunctionInfo(name=function_name, cmp_bytes={},
                         called_from=polytracker_json_obj["runtime_cfg"][function_name])
        )
    return ProgramTrace(version=version, function_data=function_data)


class TaintForestFunctionInfo(FunctionInfo):
    def __init__(
            self,
            name: str,
            forest: TaintForest,
            cmp_byte_labels: Dict[str, List[int]],
            input_byte_labels: Optional[Dict[str, List[int]]] = None,
            called_from: Iterable[str] = (),
    ):
        super().__init__(name=name, cmp_bytes={}, called_from=called_from)
        self.forest: TaintForest = forest
        self.cmp_byte_labels: Dict[str, List[int]] = cmp_byte_labels
        if input_byte_labels is None:
            self.input_byte_labels: Dict[str, List[int]] = self.cmp_byte_labels
        else:
            self.input_byte_labels = input_byte_labels
        self._cached_input_bytes: Optional[Dict[str, List[int]]] = None
        self._cached_cmp_bytes: Optional[Dict[str, List[int]]] = None

    @property
    def taint_sources(self) -> KeysView[str]:
        return self.input_byte_labels.keys()

    def source_size(self, source: str) -> int:
        if source not in self.input_byte_labels:
            raise KeyError(source)
        elif os.path.exists(source):
            return super().source_size(source)
        elif len(self.taint_sources) == 1:
            # we can exactly calculate the last byte rad from the canonical mapping
            return max(offset for _, offset in self.forest.canonical_mapping.items())
        else:
            return super().source_size(source)

    @property
    def input_bytes(self) -> Dict[str, List[int]]:
        if self._cached_input_bytes is None:
            self._cached_input_bytes = {
                source: sorted(self.forest.tainted_bytes(*labels)) for source, labels in self.input_byte_labels.items()
            }
        return self._cached_input_bytes

    @property
    def cmp_bytes(self) -> Dict[str, List[int]]:
        if self._cached_cmp_bytes is None:
            self._cached_cmp_bytes = {
                source: list(self.forest.tainted_bytes(*labels)) for source, labels in self.cmp_byte_labels.items()
            }
        return self._cached_cmp_bytes


@polytracker_version(2, 2, 0)
def parse_format_v4(polytracker_json_obj: dict, polytracker_forest_path: str) -> ProgramTrace:
    version = polytracker_json_obj["version"].split(".")
    function_data: List[FunctionInfo] = []
    tainted_functions = set()
    sources = polytracker_json_obj["canonical_mapping"].keys()
    if len(sources) != 1:
        raise ValueError(f"Expected only a single taint source, but found {sources}")
    source = next(iter(sources))
    canonical_mapping: Dict[int, int] = dict(polytracker_json_obj["canonical_mapping"][source])
    forest = TaintForest(path=polytracker_forest_path, canonical_mapping=canonical_mapping)
    for function_name, data in polytracker_json_obj["tainted_functions"].items():
        if "input_bytes" not in data:
            if "cmp_bytes" in data:
                input_bytes = {source: data["cmp_bytes"]}
            else:
                input_bytes = {}
        else:
            input_bytes = {source: data["input_bytes"]}
        if "cmp_bytes" in data:
            cmp_bytes = {source: data["cmp_bytes"]}
        else:
            cmp_bytes = input_bytes
        if function_name in polytracker_json_obj["runtime_cfg"]:
            called_from = frozenset(polytracker_json_obj["runtime_cfg"][function_name])
        else:
            called_from = frozenset()
        function_data.append(
            TaintForestFunctionInfo(
                name=function_name,
                forest=forest,
                cmp_byte_labels=cmp_bytes,
                input_byte_labels=input_bytes,
                called_from=called_from,
            )
        )
        tainted_functions.add(function_name)
    # Add any additional functions from the CFG that didn't operate on tainted bytes
    # Add any additional functions from the CFG that didn't operate on tainted bytes
    for function_name in polytracker_json_obj["runtime_cfg"].keys() - tainted_functions:
        function_data.append(
            FunctionInfo(name=function_name, cmp_bytes={},
                         called_from=polytracker_json_obj["runtime_cfg"][function_name])
        )
    return ProgramTrace(version=version, function_data=function_data)


class TraceDiffCommand(Command):
    name = "diff"
    help = "compute a diff of two program traces"

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument("polytracker_db1", type=str, help="the sqlite3 db file for the reference trace")
        # parser.add_argument("polytracker_db2", type=str, help="the sqlite3 db file for the different trace")
        parser.add_argument("input_id1", type=int, help="input id of reference trace instance")
        parser.add_argument("input_id2", type=int, help="input id of different trace instance")
        # parser.add_argument("polytracker_json1", type=str, help="the JSON file for the reference trace")
        # parser.add_argument("taint_forest_bin1", type=str, help="the taint forest file for the reference trace")
        # parser.add_argument("polytracker_json2", type=str, help="the JSON file for the different trace")
        # parser.add_argument("taint_forest_bin2", type=str, help="the taint forest file for the different trace")
        parser.add_argument("--image", type=str, default=None,
                            help="path to optionally output a visualization of the" "diff")

    def run(self, args: Namespace):
        if not os.path.exists(args.polytracker_db1):
            print(f"Error! Database file {args.polytracker_db1} not found!")
        if not os.path.exists(args.polytracker_db2):
            print(f"Error! Database file {args.polytracker_db2} not found!")
        with sqlite3.connect(args.polytracker_db1) as f:
            # trace1 = parse(json.load(f), args.taint_forest_bin1)
            trace1 = parse_sql(f, args.input_id1)
            trace2 = parse_sql(f, args.input_id2)
        # with sqlite3.connect(args.polytracker_db2) as f:
        # trace2 = parse(json.load(f), args.taint_forest_bin2)
        # trace2 = parse_sql(f)
        diff = trace1.diff(trace2)
        print(str(diff))
        if args.image is not None:
            diff.to_image().save(args.image)


class TemporalVisualization(Command):
    name = "temporal"
    help = "generate an animation of the file accesses in a runtime trace"

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument("polytracker_json", type=str, help="the JSON file for the trace")
        parser.add_argument("taint_forest_bin", type=str, help="the taint forest file for the trace")
        parser.add_argument("OUTPUT_GIF_PATH", type=str, help="the path to which to save the animation")

    def run(self, args):
        with open(args.polytracker_json, "r") as f:
            polytracker_json_obj = json.load(f)
        sources = polytracker_json_obj["canonical_mapping"].keys()
        if len(sources) != 1:
            raise ValueError(f"Expected only a single taint source, but found {sources}")
        source = next(iter(sources))
        canonical_mapping = dict(polytracker_json_obj["canonical_mapping"][source])
        del polytracker_json_obj
        forest = TaintForest(args.taint_forest_bin, canonical_mapping=canonical_mapping)
        temporal_animation(args.OUTPUT_GIF_PATH, forest)


class ListCommand(Command):
    name = "list"
    help = "list features from the database"
    parser: ArgumentParser

    def __init_arguments__(self, parser: ArgumentParser):
        self.parser = parser

    def run(self, args: Namespace) -> None:
        self.parser.print_help()


class InputListCommand(Subcommand[ListCommand]):
    name = "input"
    help = "list all inputs that were run and their ID's"
    parent_type = ListCommand

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument("polydb", type=str, help="Path to the parser's database file")

    def run(self, args: Namespace):
        if not os.path.exists(args.polydb):
            print(f"Error! Could not find {args.polydb}")
            exit(1)
        with sqlite3.connect(args.polydb) as conn:
            cursor = conn.execute("select id, path from input;")
            results = [["ID", "PATH"]] + [row for row in cursor]
            for row in results:
                print("{: <20} {: <20}".format(*row))


class TraceListCommand(Subcommand[ListCommand]):
    name = "trace"
    help = "list all inputs that were run with POLYTRACE > 0 and their ID's"
    parent_type = ListCommand

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument("polydb", type=str, help="Path to the parser's database file")

    def run(self, args: Namespace):
        if not os.path.exists(args.polydb):
            print(f"Error! Could not find {args.polydb}")
            exit(1)
        with sqlite3.connect(args.polydb) as conn:
            cursor = conn.execute("select id, trace_level, path from input where trace_level=1;")
            result = [["ID", "TRACE_LEVEL", "PATH"]] + [row for row in cursor]
            for row in result:
                print("{: <20} {: <20} {: <20}".format(*row))


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
        parser.add_argument("taint_forest_bin", type=str, help="the taint forest file for the trace")
        parser.add_argument("output_dot_path", type=str, help="the path to which to save the .dot graph")

    def run(self, args: Namespace):
        forest = TaintForest(args.taint_forest_bin)
        forest.to_graph().to_dot().save(args.output_dot_path)


class ConfigBuildCommand(Command):
    name = "config"
    help = "generate polytracker configuration files"
    parser: ArgumentParser

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument("--bb_trace", type=bool, help="trace basic blocks")
        parser.add_argument("--func_trace", type=bool, help="trace at function granularity")
        parser.add_argument("--db", type=str, help="path to store the output database")
        parser.add_argument("--track_start", type=int, help="offset to start tracking from")
        parser.add_argument("--track_end", type=int, help="offset to stop tracking at")
        parser.add_argument("--taint_ttl", type=int, help="sets the value of taint decay")
        parser.add_argument("--forest_output", type=str, help="optional output the forest to disk instead of database")
        parser.add_argument("--output", type=str, help="output for generated config file")
        self.parser = parser

    def run(self, args: Namespace):
        output_json = {}
        if not args.output:
            print("Error! No output specified")
            self.parser.print_help()
        if args.bb_trace:
            output_json["POLYTRACE"] = args.bb_trace
        if args.func_trace:
            output_json["POLYFUNC"] = args.func_trace
        if args.db:
            output_json["POLYDB"] = args.db
        if args.track_start:
            output_json["POLYSTART"] = args.track_start
        if args.track_end:
            output_json["POLYEND"] = args.track_end
        if args.taint_ttl:
            output_json["POLYTTL"] = args.taint_ttl
        if args.forest_output:
            output_json["POLYFOREST"] = args.forest_output
        with open(args.output, "w") as f:
            json.dump(output_json, f)
