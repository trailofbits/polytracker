from abc import ABC, abstractmethod
from collections import defaultdict
from enum import IntFlag
from pathlib import Path
from typing import (
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Union,
)

from cxxfilt import demangle

from polytracker.cfg import DiGraph


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
        last_input: Optional[Input] = None
        last_offset: Optional[ByteOffset] = None
        region: Optional[TaintedRegion] = None
        for offset in self:
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
        self.function_index = function_index

    @property
    def demangled_name(self) -> str:
        return demangle(self.name)

    @abstractmethod
    def taints(self) -> Taints:
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


class FunctionEntry(TraceEvent):
    def __init__(self, uid: int, name: str):
        super().__init__(uid=uid)
        self.name = name

    @property
    def caller(self) -> "BasicBlockEntry":
        prev = self.previous_event
        if isinstance(prev, FunctionReturn) and prev.function_call is not None:
            try:
                return prev.function_call.caller
            except TypeError:
                pass
        if not isinstance(prev, BasicBlockEntry):
            raise TypeError(
                f"The previous event to {self} was expected to be a BasicBlockEntry but was in fact {prev}"
            )
        return prev

    @property
    def returning_to(self) -> Optional[TraceEvent]:
        if self.function_return is not None:
            return self.function_return.returning_to
        else:
            return self.next_event

    def __repr__(self):
        return f"{self.__class__.__name__}({self.uid!r}, {self.previous_uid!r}, {self.name!r})"


class BasicBlockEntry(TraceEvent):
    @property
    def containing_function(self) -> Optional[FunctionEntry]:
        if self.function_call_uid is not None:
            try:
                return self.trace[self.function_call_uid]
            except KeyError:
                return None
        else:
            return None

    @property
    def function_name(self) -> str:
        if self._function_name is None:
            func = self.containing_function
            if func is None:
                raise ValueError(f"The function name of {self!r} is not known!")
            self._function_name = func.name
        return self._function_name

    @property
    def consumed_tokens(self) -> Iterable[bytes]:
        start_offset: Optional[int] = None
        last_offset: Optional[int] = None
        for offset in self.consumed:
            if start_offset is None:
                start_offset = last_offset = offset
            elif start_offset + 1 != offset:
                # this is not a contiguous byte sequence
                # so yield the previous token
                yield self.trace.inputstr[start_offset : last_offset + 1]  # type: ignore
                start_offset = last_offset = offset
            else:
                # this is a contiguous byte sequence, so update its end
                last_offset = offset
        if start_offset is not None:
            yield self.trace.inputstr[start_offset : last_offset + 1]  # type: ignore

    @property
    def basic_block(self) -> BasicBlock:
        return self.trace.get_basic_block(self)

    def __str__(self):
        return f"{self.basic_block!s}#{self.entry_count}"


class FunctionReturn(TraceEvent):
    def __init__(
        self,
        uid: int,
        name: str,
        previous_uid: Optional[int] = None,
        next_uid: Optional[int] = None,
        call_event_uid: Optional[int] = None,
        returning_to_uid: Optional[int] = None,
    ):
        super().__init__(uid=uid, previous_uid=previous_uid, next_uid=next_uid)
        self.function_name: str = name
        self.returning_to_uid: Optional[int] = returning_to_uid
        self.call_event_uid: Optional[int] = call_event_uid
        self._returning_to: Optional[BasicBlockEntry] = None
        self._function_call: Optional[Union[FunctionEntry, ValueError]] = None

    def __repr__(self):
        return (
            f"{self.__class__.__name__}({self.uid!r}, {self.previous_uid!r}, {self.function_name!r}, "
            f"{self.returning_to_uid!r})"
        )

    @property
    def returning_to(self) -> Optional[TraceEvent]:
        if self._returning_to is None:
            if self.returning_to_uid is None:
                return self.next_event
            self._returning_to = self.trace[self.returning_to_uid]
        return self._returning_to

    def trace(self, pttrace: "ProgramTrace"):
        TraceEvent.trace.fset(self, pttrace)  # type: ignore
        if self.function_call.function_return is None:
            self.function_call.function_return = self
        elif self.function_call.function_return is not self:
            raise ValueError(
                f"Function call {self.function_call} was expected to return to {self}, "
                f"but instead returns to {self.function_call.function_return}"
            )

    @property
    def function_call(self) -> FunctionEntry:
        if self._function_call is None:
            if self.call_event_uid is not None:
                fc = self.trace[self.call_event_uid]
                if isinstance(fc, FunctionEntry):
                    self._function_call = fc
                    return fc
                else:
                    self._function_call = ValueError(
                        f"Function return {self!r} was associated with "
                        f"function call uid {self.call_event_uid}, but this was "
                        f"not a function call: {fc!r}"
                    )
                    raise self._function_call
            prev: Optional[TraceEvent] = self.previous
            subcalls = 0
            while prev is not None:
                if isinstance(prev, FunctionEntry):
                    if subcalls == 0:
                        break
                    else:
                        subcalls -= 1
                elif isinstance(prev, FunctionReturn):
                    if prev._function_call is not None:
                        if isinstance(prev._function_call, FunctionEntry):
                            prev = prev._function_call.caller.previous
                        else:
                            break
                    else:
                        subcalls += 1
                prev = prev.previous  # type: ignore
            if isinstance(prev, FunctionEntry):
                self._function_call = prev
            else:
                self._function_call = ValueError(
                    f"Could not find the function call associated with return {self}"
                )
        if isinstance(self._function_call, ValueError):
            raise self._function_call
        return self._function_call  # type: ignore


class ProgramTrace(ABC):
    _cfg: Optional[DiGraph[BasicBlock]] = None

    @abstractmethod
    def __len__(self) -> int:
        """Returns the total number of events in this trace"""
        raise NotImplementedError()

    @abstractmethod
    def __iter__(self) -> Iterable[TraceEvent]:
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
    def get_basic_block(self, entry: BasicBlockEntry) -> BasicBlock:
        raise NotImplementedError()

    @abstractmethod
    def __getitem__(self, uid: int) -> TraceEvent:
        raise NotImplementedError()

    @abstractmethod
    def __contains__(self, uid: int):
        raise NotImplementedError()

    @property
    def cfg(self) -> DiGraph[BasicBlock]:
        if self._cfg is None:
            self._cfg = DiGraph()
            for bb in self.basic_blocks:
                self._cfg.add_node(bb)
                for child in bb.children:
                    self._cfg.add_edge(bb, child)
        return self._cfg

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
