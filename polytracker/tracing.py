from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace, REMAINDER
from collections import defaultdict
from enum import IntFlag
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Union,
)
import weakref

from cxxfilt import demangle

from .cfg import DiGraph
from .plugins import Command, Subcommand
from .repl import PolyTrackerREPL


class BasicBlockType(IntFlag):
    """
    Basic block types

    This should be kept in parity with the enum in /polytracker/include/polytracker/basic_block_types.h

    """

    UNKNOWN = 0
    """We don't know what kind of BB this is"""
    STANDARD = 1
    """A standard, unremarkable BB"""
    CONDITIONAL = 2
    """Any BB that contains a conditional branch"""
    LOOP_ENTRY = 6
    """A BB that is an entrypoint into a loop"""
    LOOP_EXIT = 10
    """A BB that is an exit to a loop"""
    FUNCTION_ENTRY = 16
    """A BB that is the first inside of its function"""
    FUNCTION_EXIT = 32
    """A BB that exits a function (i.e., it contains a return instruction)"""
    FUNCTION_RETURN = 64
    """A BB that is executed immediately after a CallInst returns"""
    FUNCTION_CALL = 128
    """A BB that contains a CallInst"""


class Input:
    def __init__(
            self,
            uid: int,
            path: str,
            size: int,
            track_start: int = 0,
            track_end: Optional[int] = None,
            content: Optional[bytes] = None
    ):
        self.uid: int = uid
        self.path: str = path
        self.size: int = size
        self.track_start: int = track_start
        if track_end is None:
            self.track_end: int = size
        else:
            self.track_end = track_end
        self.stored_content: Optional[bytes] = content

    @property
    def content(self) -> bytes:
        if self.stored_content is not None:
            return self.stored_content
        elif not Path(self.path).exists():
            raise ValueError(f"Input {self.uid} did not have its content stored to the database (the instrumented "
                             f"binary was likely run with POLYSAVEINPUT=0) and the associated path {self.path!r} "
                             "does not exist!")
        with open(self.path, "rb") as f:
            self.stored_content = f.read()
        return self.stored_content

    def __hash__(self):
        return self.uid

    def __eq__(self, other):
        return isinstance(other, Input) and self.uid == other.uid and self.path == other.path


class TaintedRegion:
    def __init__(self, source: Input, offset: int, length: int):
        self.source: Input = source
        self.offset: int = offset
        self.length: int = length

    @property
    def value(self) -> bytes:
        return self.source.content[self.offset:self.offset+self.length]

    def __getitem__(self, index_or_slice: Union[int, slice]) -> "TaintedRegion":
        if isinstance(index_or_slice, slice):
            if index_or_slice.step is not None and index_or_slice.step != 1:
                raise ValueError("TaintedRegion only supports slices with step == 1")
            start = slice.start
            if start < 0:
                start = max(self.length + start, 0)
            stop = slice.stop
            if stop < 0:
                stop = self.length + stop
            if start >= stop or start >= self.length or stop <= 0:
                return TaintedRegion(source=self.source, offset=self.offset, length=0)
            return TaintedRegion(source=self.source, offset=self.offset+start, length=stop-start)
        elif index_or_slice < 0 or index_or_slice >= self.length:
            raise IndexError(index_or_slice)
        else:
            return ByteOffset(source=self.source, offset=self.offset + index_or_slice)

    def __bytes__(self):
        return self.value

    def __hash__(self):
        return hash((self.source, self.offset))

    def __eq__(self, other):
        return isinstance(other, TaintedRegion) and self.source == other.source and self.offset == other.offset and \
               self.length == other.length

    def __lt__(self, other):
        return isinstance(other, TaintedRegion) and \
               (self.source.uid, self.offset, self.length) < (other.source.uid, other.offset, other.length)


class ByteOffset(TaintedRegion):
    def __init__(self, source: Input, offset: int):
        super().__init__(source=source, offset=offset, length=1)


class TaintDiff:
    def __init__(self, taints1: "Taints", taints2: "Taints"):
        self.taints1: Taints = taints1
        self.taints2: Taints = taints2
        self._only_in_first: Optional[List[ByteOffset]] = None
        self._only_in_second: Optional[List[ByteOffset]] = None

    def _diff(self):
        if self._only_in_first is not None:
            return
        in_first = set(self.taints1)
        in_second = set(self.taints2)
        self._only_in_first = sorted(in_first - in_second)
        self._only_in_second = sorted(in_second - in_first)

    @property
    def bytes_only_in_first(self) -> List[ByteOffset]:
        self._diff()
        return self._only_in_first  # type: ignore

    @property
    def regions_only_in_first(self) -> Iterator[TaintedRegion]:
        yield from Taints.to_regions(self.bytes_only_in_first, is_sorted=True)

    @property
    def bytes_only_in_second(self) -> List[ByteOffset]:
        self._diff()
        return self._only_in_second  # type: ignore

    @property
    def regions_only_in_second(self) -> Iterator[TaintedRegion]:
        yield from Taints.to_regions(self.bytes_only_in_second, is_sorted=True)

    def __bool__(self):
        return bool(self.bytes_only_in_first) or bool(self.bytes_only_in_second)

    def __eq__(self, other):
        return isinstance(other, TaintDiff) and self.taints1 == other.taints1 and self.taints2 == other.taints2


class Taints:
    def __init__(self, byte_offsets: Iterable[ByteOffset]):
        offsets_by_source: Dict[Input, Set[ByteOffset]] = defaultdict(set)
        for offset in byte_offsets:
            offsets_by_source[offset.source].add(offset)
        self._offsets_by_source: Dict[Input, List[ByteOffset]] = {
            source: sorted(offsets)
            for source, offsets in offsets_by_source.items()
        }

    def sources(self) -> Set[Input]:
        return set(self._offsets_by_source.keys())

    def from_source(self, source: Input) -> "Taints":
        return Taints(self._offsets_by_source.get(source, ()))

    def regions(self) -> Iterator[TaintedRegion]:
        return Taints.to_regions(self, is_sorted=True)

    @staticmethod
    def to_regions(offsets: Iterable[ByteOffset], is_sorted: bool = False) -> Iterator[TaintedRegion]:
        """Converts the list of byte offsets into contiguous regions."""
        last_input: Optional[Input] = None
        last_offset: Optional[ByteOffset] = None
        region: Optional[TaintedRegion] = None
        if not is_sorted:
            offsets = sorted(offsets)
        for offset in offsets:
            if last_input is None:
                last_input = offset.source
            elif last_input != offset.source or (last_offset is not None and last_offset.offset != offset.offset - 1):
                if region is not None:
                    yield region
                region = None
            last_offset = offset
            if region is None:
                region = TaintedRegion(source=offset.source, offset=offset.offset, length=offset.length)
            else:
                region.length += offset.length
        if region is not None:
            yield region

    def find(self, byte_sequence: Union[int, str, bytes]) -> Iterator[TaintedRegion]:
        """Finds the start of any matching tainted byte sequence in this set of taints"""
        if isinstance(byte_sequence, str):
            byte_sequence = byte_sequence.encode("utf-8")
        elif isinstance(byte_sequence, int):
            byte_sequence = bytes([byte_sequence])
        for region in self.regions():
            offset = 0
            while True:
                content = region.value
                offset = content.find(byte_sequence, offset)
                if offset >= 0:
                    yield region[offset:offset+len(byte_sequence)]
                else:
                    break

    def diff(self, other: "Taints") -> TaintDiff:
        return TaintDiff(self, other)

    def __contains__(self, byte_sequence: Union[int, str, bytes]):
        try:
            next(iter(self.find(byte_sequence)))
            return True
        except StopIteration:
            return False

    def __len__(self):
        return sum(map(len, self._offsets_by_source.values()))

    def __iter__(self) -> Iterator[ByteOffset]:
        for offsets in self._offsets_by_source.values():
            yield from offsets

    def __bool__(self):
        return bool(len(self))


class Function:
    def __init__(self, name: str, function_index: int):
        self.name: str = name
        self.basic_blocks: List[BasicBlock] = []
        self.function_index: int = function_index

    @property
    def demangled_name(self) -> str:
        return demangle(self.name)

    @abstractmethod
    def taints(self) -> Taints:
        raise NotImplementedError()

    @abstractmethod
    def calls_to(self) -> Set["Function"]:
        raise NotImplementedError()

    @abstractmethod
    def called_from(self) -> Set["Function"]:
        raise NotImplementedError()

    def __hash__(self):
        return self.function_index

    def __eq__(self, other):
        return (
            isinstance(other, Function) and self.function_index == other.function_index
        )

    def __str__(self):
        return self.name


class BasicBlock:
    def __init__(self, function: Function, index_in_function: int):
        self.function: Function = function
        self.index_in_function: int = index_in_function
        self.children: Set[BasicBlock] = set()
        self.predecessors: Set[BasicBlock] = set()
        function.basic_blocks.append(self)

    @abstractmethod
    def taints(self) -> Taints:
        raise NotImplementedError()

    def is_loop_entry(self, trace: "ProgramTrace") -> bool:
        predecessors = set(p for p in self.predecessors if self.function == p.function)
        if len(predecessors) < 2:
            return False
        dominators = set(trace.cfg.dominator_forest.predecessors(self))
        # we are a loop entry if we have one predecessor that dominates us and another that doesn't
        if not any(p in predecessors for p in dominators):
            return False
        return any(p not in dominators for p in predecessors)

    def is_conditional(self, trace: "ProgramTrace") -> bool:
        # we are a conditional if we have at least two children in the same function and we are not a loop entry
        return sum(
            1 for c in self.children if c.function == self.function
        ) >= 2 and not self.is_loop_entry(trace)

    def __hash__(self):
        return hash((self.function, self.index_in_function))

    def __eq__(self, other):
        return (
            isinstance(other, BasicBlock)
            and other.function == self.function
            and self.index_in_function == other.index_in_function
        )

    def __str__(self):
        return f"{self.function!s}@{self.index_in_function}"


class TraceEvent:
    def __init__(self, uid: int):
        self.uid: int = uid

    @property
    @abstractmethod
    def basic_block(self) -> BasicBlock:
        raise NotImplementedError()

    @property
    def function(self) -> Function:
        return self.basic_block.function

    @abstractmethod
    def taints(self) -> Taints:
        raise NotImplementedError()

    @property
    @abstractmethod
    def previous_event(self) -> Optional["TraceEvent"]:
        raise NotImplementedError()

    @property
    @abstractmethod
    def next_event(self) -> Optional["TraceEvent"]:
        raise NotImplementedError()

    @property
    def next_control_flow_event(self) -> Optional["ControlFlowEvent"]:
        next_event = self.next_event
        while next_event is not None:
            if isinstance(next_event, ControlFlowEvent):
                return next_event
            next_event = next_event.next_event
        return None

    @property
    def previous_control_flow_event(self) -> Optional["ControlFlowEvent"]:
        previous_event = self.previous_event
        while previous_event is not None:
            if isinstance(previous_event, ControlFlowEvent):
                return previous_event
            previous_event = previous_event.previous_event
        return None

    @property
    @abstractmethod
    def next_global_event(self) -> Optional["TraceEvent"]:
        raise NotImplementedError()

    @property
    @abstractmethod
    def previous_global_event(self) -> Optional["TraceEvent"]:
        raise NotImplementedError()

    @property
    @abstractmethod
    def function_entry(self) -> Optional["FunctionEntry"]:
        raise NotImplementedError()

    def __eq__(self, other):
        return isinstance(other, TraceEvent) and other.uid == self.uid

    def __lt__(self, other):
        return self.uid < other.uid

    def __hash__(self):
        return self.uid


class ControlFlowEvent(TraceEvent):
    pass


class FunctionEntry(ControlFlowEvent):
    def __init__(self, uid: int):
        super().__init__(uid=uid)

    @property
    def caller(self) -> "BasicBlockEntry":
        prev = self.previous_control_flow_event
        while prev is not None:
            if isinstance(prev, BasicBlockEntry):
                return prev
            elif isinstance(prev, FunctionReturn):
                prev = prev.function_entry
                if prev is None:
                    break
            prev = prev.previous_control_flow_event
        raise ValueError(f"Unable to determine the caller for {self}")

    @property
    def entrypoint(self) -> Optional["BasicBlockEntry"]:
        next_event = self.next_control_flow_event
        if isinstance(next_event, BasicBlockEntry):
            if next_event.function_entry != self:
                raise ValueError(f"Unexpected basic block: {next_event}")
            return next_event
        return None

    @property
    @abstractmethod
    def function_return(self) -> Optional["FunctionReturn"]:
        raise NotImplementedError()

    def __repr__(self):
        return f"{self.__class__.__name__}({self.uid!r}, {self.function.name!r})"


class TaintAccess(TraceEvent):
    def __repr__(self):
        return f"{self.__class__.__name__}({self.uid!r})"


class BasicBlockEntry(ControlFlowEvent):
    def entry_count(self) -> int:
        """Calculates the number of times this basic block has been entered in the current stack frame"""
        entry_count = 0
        event = self.previous_control_flow_event
        while event is not None and event != self.function_entry:
            if isinstance(event, FunctionReturn):
                event = event.function_entry
            elif isinstance(event, BasicBlockEntry) and event.basic_block == self.basic_block:
                entry_count += 1
            if event is not None:
                event = event.previous_control_flow_event
        return entry_count

    @property
    def called_function(self) -> Optional[FunctionEntry]:
        """
        Returns the function entry event called from this basic block, or None if this basic block does not call
        a function

        """
        next_event = self.previous_control_flow_event
        if isinstance(next_event, FunctionEntry):
            return next_event
        return None

    def next_basic_block_in_function(self) -> Optional["BasicBlockEntry"]:
        """Finds the next basic block in this function"""
        next_event = self.next_control_flow_event
        while next_event is not None:
            if isinstance(next_event, BasicBlockEntry):
                if next_event.function_entry == self.function_entry:
                    return next_event
                else:
                    break
            elif isinstance(next_event, FunctionEntry):
                next_event = next_event.function_return
                if next_event is None:
                    break
                next_event = next_event.next_control_flow_event
            else:
                break
        return None

    @property
    def consumed_tokens(self) -> Iterable[bytes]:
        return tuple(r.value for r in self.taints().regions())

    def __str__(self):
        return f"{self.basic_block!s}#{self.entry_count()}"


class FunctionReturn(ControlFlowEvent):
    def __init__(self, uid: int):
        super().__init__(uid=uid)

    def __repr__(self):
        return (
            f"{self.__class__.__name__}({self.uid!r})"
        )

    @property
    def returning_to(self) -> Optional[BasicBlockEntry]:
        next_event = self.next_control_flow_event
        if isinstance(next_event, BasicBlockEntry):
            return next_event
        return None

    @property
    def returning_from(self) -> Function:
        entry = self.function_entry
        if entry is None:
            raise ValueError(f"Unable to determine the function entry object associated with function return {self!r}")
        return entry.basic_block.function


class ProgramTrace(ABC):
    _cfg: Optional[DiGraph[BasicBlock]] = None
    _func_cfg: Optional[DiGraph[Function]] = None

    @abstractmethod
    def __len__(self) -> int:
        """Returns the total number of events in this trace"""
        raise NotImplementedError()

    @abstractmethod
    def __iter__(self) -> Iterator[TraceEvent]:
        """Iterates over all of the events in this trace, in order"""
        raise NotImplementedError()

    @property
    @abstractmethod
    def functions(self) -> Iterable[Function]:
        raise NotImplementedError()

    @property
    @abstractmethod
    def basic_blocks(self) -> Iterable[BasicBlock]:
        raise NotImplementedError()

    @abstractmethod
    def get_function(self, name: str) -> Function:
        raise NotImplementedError()

    @abstractmethod
    def has_function(self, name: str) -> bool:
        raise NotImplementedError()

    @abstractmethod
    def access_sequence(self) -> Iterator[TaintAccess]:
        raise NotImplementedError()

    @property
    @abstractmethod
    def num_accesses(self) -> int:
        raise NotImplementedError()

    @property
    @abstractmethod
    def inputs(self) -> Iterable[Input]:
        raise NotImplementedError()

    @abstractmethod
    def __getitem__(self, uid: int) -> TraceEvent:
        raise NotImplementedError()

    @abstractmethod
    def __contains__(self, uid: int):
        raise NotImplementedError()

    @property
    def cfg(self) -> DiGraph[BasicBlock]:
        if not hasattr(self, "_cfg") or self._cfg is None:
            setattr(self, "_cfg", DiGraph())
            for bb in self.basic_blocks:
                self._cfg.add_node(bb)  # type: ignore
                for child in bb.children:
                    self._cfg.add_edge(bb, child)  # type: ignore
        return self._cfg  # type: ignore

    @property
    def function_cfg(self) -> DiGraph[Function]:
        if not hasattr(self, "_func_cfg") or self._func_cfg is None:
            setattr(self, "_func_cfg", DiGraph())
            for func in self.functions:
                self._func_cfg.add_node(func)  # type: ignore
                for child in func.calls_to():
                    self._func_cfg.add_edge(func, child)  # type: ignore
        return self._func_cfg  # type: ignore

    def cfg_roots(self) -> Iterable[BasicBlock]:
        for bb in self.basic_blocks:
            if not bb.predecessors:
                yield bb

    def is_cfg_connected(self) -> bool:
        roots = iter(self.cfg_roots())
        try:
            next(roots)
        except StopIteration:
            # there are no roots
            return False
        # there is at least one root
        try:
            next(roots)
            # there is more than one root
            return False
        except StopIteration:
            return True


class TraceCommand(Command):
    name = "trace"
    help = "commands related to tracing"
    parser: ArgumentParser

    def __init_arguments__(self, parser: ArgumentParser):
        self.parser = parser

    def run(self, args: Namespace):
        self.parser.print_help()


class RunTraceCommand(Subcommand[TraceCommand]):
    name = "run"
    help = "run an instrumented binary"
    parent_type = TraceCommand

    def __init_arguments__(self, parser):
        parser.add_argument("--no-bb-trace", action="store_true", help="do not trace at the basic block level")
        parser.add_argument("--output-db", "-o", type=str, default="polytracker.db",
                            help="path to the output database (default is polytracker.db)")
        parser.add_argument("INSTRUMENTED_BINARY", type=str, help="the instrumented binary to run")
        parser.add_argument("INPUT_FILE", type=str, help="the file to track")
        parser.add_argument("args", nargs=REMAINDER)

    @staticmethod
    @PolyTrackerREPL.register("run_trace")
    def run_trace(
            instrumented_binary_path: str,
            input_file_path: str,
            no_bb_trace: bool = False,
            output_db_path: Optional[str] = None,
            args=(),
            return_trace: bool = True
    ) -> Union[ProgramTrace, int]:
        """
        Runs an instrumented binary and returns the resulting trace

        Args:
            instrumented_binary_path: path to the instrumented binary
            input_file_path: input file to track
            no_bb_trace: if True, only functions will be traced and not basic blocks
            output_db_path: path to save the output database
            args: additional arguments to pass the binary
            return_trace: if True (the default), return the resulting ProgramTrace. If False, just return the exit code.

        Returns: The program trace or the instrumented binary's exit code

        """
        can_run_natively = PolyTrackerREPL.registered_globals["CAN_RUN_NATIVELY"]

        if output_db_path is None:
            # use a temporary file
            tmpdir: Optional[TemporaryDirectory] = TemporaryDirectory()
            output_db_path = str(Path(tmpdir.name) / "polytracker.db")  # type: ignore
        else:
            tmpdir = None

        if Path(args.output_db).exists():
            PolyTrackerREPL.warning(f"<style fg=\"gray\">{args.output.db}</style> already exists")

        cmd_args = [instrumented_binary_path] + args.args + [input_file_path]
        env = {
            "POLYPATH": input_file_path,
            "POLYTRACE": ["1", "0"][no_bb_trace],
            "POLYDB": output_db_path
        }
        if can_run_natively:
            retval = subprocess.call(cmd_args, env=env)  # type: ignore
        else:
            run_command = PolyTrackerREPL.commands["docker_run"]
            retval = run_command(args=cmd_args, interactive=True, env=env)
        if return_trace:
            from . import PolyTrackerTrace
            trace = PolyTrackerTrace.load(output_db_path)
            if tmpdir is not None:
                weakref.finalize(trace, tmpdir.cleanup)
            return trace
        else:
            if tmpdir is not None:
                tmpdir.cleanup()
            return retval

    def run(self, args: Namespace):
        retval = RunTraceCommand.run_trace(
            instrumented_binary_path=args.INSTRUMENTED_BINARY,
            input_file_path=args.INPUT_FILE,
            no_bb_trace=args.no_bb_trace,
            output_db_path=args.output_db,
            args=args.args,
            return_trace=False
        )
        if retval == 0:
            print(f"Trace saved to {args.output_db}")
        return retval


class CFGTraceCommand(Subcommand[TraceCommand]):
    name = "cfg"
    help = "export a trace as an annotated cfg"
    parent_type = TraceCommand

    def __init_arguments__(self, parser):
        parser.add_argument("TRACE_DB", type=str, help="path to the trace database")

    def run(self, args: Namespace):
        from . import PolyTrackerTrace
        db = PolyTrackerTrace.load(args.TRACE_DB)
        db.function_cfg.to_dot().save("trace.dot")
