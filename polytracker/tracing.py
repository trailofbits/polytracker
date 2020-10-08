import json
from abc import ABCMeta
import sys
from typing import Any, BinaryIO, cast, Dict, IO, Iterable, Iterator, List, Optional, Set, Tuple, Union

from tqdm import tqdm

from .bitmap import Bitmap, BitmapValue
from polytracker.cfg import DiGraph

if sys.version_info.major == 3 and sys.version_info.minor < 8:
    from typing_extensions import Protocol  # type: ignore
else:
    from typing import Protocol  # type: ignore


class TraceEventConstructor(Protocol):
    def __call__(self, **kwargs) -> "TraceEvent":
        ...


EVENTS_BY_TYPE: Dict[str, TraceEventConstructor] = {}


class BasicBlockType(Bitmap):
    """
    Basic block types

    This should be kept in parity with the enum in /polytracker/include/polytracker/basic_block_types.h

    """

    UNKNOWN = BitmapValue(0)
    """We don't know what kind of BB this is"""
    STANDARD = BitmapValue(1)
    """A standard, unremarkable BB"""
    CONDITIONAL = BitmapValue(2)
    """Any BB that contains a conditional branch"""
    LOOP_ENTRY = BitmapValue(6)
    """A BB that is an entrypoint into a loop"""
    LOOP_EXIT = BitmapValue(10)
    """A BB that is an exit to a loop"""
    FUNCTION_ENTRY = BitmapValue(16)
    """A BB that is the first inside of its function"""
    FUNCTION_EXIT = BitmapValue(32)
    """A BB that exits a function (i.e., it contains a return instruction)"""
    FUNCTION_RETURN = BitmapValue(64)
    """A BB that is executed immediately after a CallInst returns"""
    FUNCTION_CALL = BitmapValue(128)
    """A BB that contains a CallInst"""


class Function:
    def __init__(self, name: str, function_index: int):
        self.name: str = name
        self.basic_blocks: List[BasicBlock] = []
        self.function_index = function_index

    def __hash__(self):
        return self.function_index

    def __eq__(self, other):
        return isinstance(other, Function) and self.function_index == other.function_index

    def __str__(self):
        return self.name


class BasicBlock:
    def __init__(self, function: Function, index_in_function: int):
        self.function: Function = function
        self.index_in_function: int = index_in_function
        self.children: Set[BasicBlock] = set()
        self.predecessors: Set[BasicBlock] = set()
        function.basic_blocks.append(self)

    def is_loop_entry(self, trace: "PolyTrackerTrace") -> bool:
        predecessors = set(p for p in self.predecessors if self.function == p.function)
        if len(predecessors) < 2:
            return False
        dominators = set(trace.cfg.dominator_forest.predecessors(self))
        # we are a loop entry if we have one predecessor that dominates us and another that doesn't
        if not any(p in predecessors for p in dominators):
            return False
        return any(p not in dominators for p in predecessors)

    def is_conditional(self, trace: "PolyTrackerTrace") -> bool:
        # we are a conditional if we have at least two children in the same function and we are not a loop entry
        return sum(1 for c in self.children if c.function == self.function) >= 2 and not self.is_loop_entry(trace)

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


class FunctionInvocation:
    def __init__(self, function: Function, call: "FunctionCall", ret: "FunctionReturn"):
        self.function: Function = function
        self.call: FunctionCall = call
        self.ret: FunctionReturn = ret


class TraceEventMeta(ABCMeta):
    def __init__(cls, name, bases, clsdict):
        if len(cls.mro()) > 2 and not cls.__abstractmethods__ and hasattr(cls, "event_type"):
            if cls.event_type in EVENTS_BY_TYPE:
                raise ValueError(
                    f"Class {cls.__name__} cannot register with event type {cls.event_type} because "
                    f"that type is already used by {EVENTS_BY_TYPE[cls.event_type].__name__}"
                )
            EVENTS_BY_TYPE[cls.event_type] = cls
        super().__init__(name, bases, clsdict)


class TraceEvent(metaclass=TraceEventMeta):
    event_type: str = "TraceEvent"

    def __init__(self, uid: int, previous_uid: Optional[int] = None, next_uid: Optional[int] = None):
        self.uid: int = uid
        self.previous_uid: Optional[int] = previous_uid
        self.next_uid: Optional[int] = next_uid
        self._trace: Optional[PolyTrackerTrace] = None

    @property
    def has_trace(self) -> bool:
        return self._trace is not None

    @property
    def trace(self) -> "PolyTrackerTrace":
        if self._trace is None:
            raise RuntimeError(
                f"The trace for event {self!r} has not been set!" "Did you call `.trace` before the entire trace was loaded?"
            )
        return self._trace

    @trace.setter
    def trace(self, pttrace: "PolyTrackerTrace"):
        if self._trace is not None:
            raise ValueError(
                f"Cannot assign event {self} to trace {pttrace} because " "it is already assigned to trace {self._trace}"
            )
        self._trace = pttrace

    def initialized(self):
        """Callback for when all events in a PolyTrackerTrace are ready for use"""
        pass

    @property
    def previous(self) -> Optional["TraceEvent"]:
        if self.previous_uid is None:
            return None
        else:
            return self.trace[self.previous_uid]

    @property
    def next_event(self) -> Optional["TraceEvent"]:
        if self.next_uid is None:
            return None
        else:
            return self.trace[self.next_uid]

    @staticmethod
    def parse(json_obj: Dict[str, Any]) -> "TraceEvent":
        if "type" not in json_obj:
            raise KeyError('The JSON object must contain a key "type" for the event type')
        elif json_obj["type"] not in EVENTS_BY_TYPE:
            raise ValueError(f"Unknown event type {json_obj['type']}; valid types are {list(EVENTS_BY_TYPE.keys())!r}")
        event_type: str = json_obj["type"]
        arguments: Dict[str, Any] = json_obj.copy()
        del arguments["type"]
        return EVENTS_BY_TYPE[event_type](**arguments)

    def __eq__(self, other):
        return isinstance(other, TraceEvent) and other.uid == self.uid

    def __lt__(self, other):
        return self.uid < other.uid

    def __hash__(self):
        return self.uid


class FunctionCall(TraceEvent):
    event_type = "FunctionCall"

    def __init__(
        self,
        uid: int,
        name: str,
        previous_uid: Optional[int] = None,
        next_uid: Optional[int] = None,
        return_uid: Optional[int] = None,
        consumes_bytes: bool = True,
    ):
        super().__init__(uid=uid, previous_uid=previous_uid, next_uid=next_uid)
        self.name = name
        self.function_return: Optional[FunctionReturn] = None
        self.entrypoint: Optional[BasicBlockEntry] = None
        self.consumes_bytes: bool = consumes_bytes
        self.return_uid: Optional[int] = return_uid

    def basic_blocks(self) -> Iterator["BasicBlockEntry"]:
        """Yields all of the basic block entries in this function call"""
        event: Optional[TraceEvent] = self.entrypoint
        while event is not None:
            if isinstance(event, BasicBlockEntry):
                if event.containing_function == self:
                    yield event
                event = event.next_event
            elif isinstance(event, FunctionCall):
                event = event.function_return
            elif isinstance(event, FunctionReturn):
                if event == self.function_return:
                    break
                event = event.next_event

    @TraceEvent.trace.setter  # type: ignore
    def trace(self, pttrace: "PolyTrackerTrace"):
        TraceEvent.trace.fset(self, pttrace)  # type: ignore
        if self.return_uid is not None and self.function_return is None:
            self.function_return = self.trace[self.return_uid]
        try:
            self.caller.called_function = self
        except TypeError as e:
            pass

    @property
    def caller(self) -> "BasicBlockEntry":
        prev = self.previous
        if isinstance(prev, FunctionReturn) and prev.function_call is not None:
            try:
                return prev.function_call.caller
            except TypeError:
                pass
        if not isinstance(prev, BasicBlockEntry):
            raise TypeError(f"The previous event to {self} was expected to be a BasicBlockEntry but was in fact {prev}")
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
    event_type = "BasicBlockEntry"

    def __init__(
        self,
        uid: int,
        function_index: int,
        bb_index: int,
        global_index: int,
        function_call_uid: Optional[int] = None,
        function_name: Optional[str] = None,
        previous_uid: Optional[int] = None,
        next_uid: Optional[int] = None,
        entry_count: int = 1,
        consumed: Iterable[int] = (),
        last_consumed: Iterable[int] = (),
        types: Iterable[str] = (),
    ):
        super().__init__(uid=uid, previous_uid=previous_uid, next_uid=next_uid)
        if entry_count < 1:
            raise ValueError("entry_count must be a natural number")
        self.entry_count: int = entry_count
        self._function_name: Optional[str] = function_name
        self.function_call_uid: Optional[int] = function_call_uid
        """The UID of the function containing this basic block"""
        self.function_index: int = function_index
        self.bb_index: int = bb_index
        self.global_index: int = global_index
        self.consumed: List[int] = list(consumed)
        """The list of input byte offsets \"touched\" during this basic block execution"""
        self.last_consumed: List[int] = list(last_consumed)
        """The subset of self.consumed for which this was the last basic block in the trace to ever consume them"""
        self.called_function: Optional[FunctionCall] = None
        """The function this basic block calls"""
        self.types: List[str] = list(types)
        self.bb_type: BasicBlockType = cast(BasicBlockType, BasicBlockType.UNKNOWN)
        for ty in types:
            bb_type = BasicBlockType.get(ty.upper())
            if bb_type is None:
                raise ValueError(f"Unknown basic block type: {ty!r} in basic block entry {uid}")
            self.bb_type |= bb_type
        self.children: List[BasicBlockEntry] = []

    @property
    def containing_function(self) -> Optional[FunctionCall]:
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

    @TraceEvent.trace.setter  # type: ignore
    def trace(self, pttrace: "PolyTrackerTrace"):
        TraceEvent.trace.fset(self, pttrace)  # type: ignore
        if BasicBlockType.FUNCTION_ENTRY in self.bb_type and isinstance(self.previous, FunctionCall):  # type: ignore
            self.previous.entrypoint = self
        if isinstance(self.previous, BasicBlockEntry):
            self.previous.children.append(self)

    @property
    def consumed_tokens(self) -> Iterator[bytes]:
        return self._consumed_tokens(self.consumed)

    @property
    def last_consumed_tokens(self) -> Iterator[bytes]:
        return self._consumed_tokens(self.last_consumed)

    def _consumed_tokens(self, offset_list: Iterable[int]) -> Iterator[bytes]:
        start_offset: Optional[int] = None
        last_offset: Optional[int] = None
        for offset in sorted(offset_list):
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
    event_type = "FunctionReturn"

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
        self._function_call: Optional[Union[FunctionCall, ValueError]] = None

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

    @TraceEvent.trace.setter  # type: ignore
    def trace(self, pttrace: "PolyTrackerTrace"):
        TraceEvent.trace.fset(self, pttrace)  # type: ignore
        if self.function_call.function_return is None:
            self.function_call.function_return = self
        elif self.function_call.function_return is not self:
            raise ValueError(
                f"Function call {self.function_call} was expected to return to {self}, "
                f"but instead returns to {self.function_call.function_return}"
            )

    @property
    def function_call(self) -> FunctionCall:
        if self._function_call is None:
            if self.call_event_uid is not None:
                fc = self.trace[self.call_event_uid]
                if isinstance(fc, FunctionCall):
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
                if isinstance(prev, FunctionCall):
                    if subcalls == 0:
                        break
                    else:
                        subcalls -= 1
                elif isinstance(prev, FunctionReturn):
                    if prev._function_call is not None:
                        if isinstance(prev._function_call, FunctionCall):
                            prev = prev._function_call.caller.previous
                        else:
                            break
                    else:
                        subcalls += 1
                prev = prev.previous  # type: ignore
            if isinstance(prev, FunctionCall):
                self._function_call = prev
            else:
                self._function_call = ValueError(f"Could not find the function call associated with return {self}")
        if isinstance(self._function_call, ValueError):
            raise self._function_call
        return self._function_call  # type: ignore


class PolyTrackerTrace:
    def __init__(self, events: List[TraceEvent], inputstr: bytes):
        self.events: List[TraceEvent] = sorted(events)
        self.events_by_uid: Dict[int, TraceEvent] = {
            event.uid: event for event in tqdm(events, leave=False, unit=" events", desc="building UID map")
        }
        self.entrypoint: Optional[BasicBlockEntry] = None
        for event in tqdm(self.events, unit=" events", leave=False, desc="initializing trace events"):
            if event.has_trace:
                raise ValueError(f"Event {event} is already associated with trace {event.trace}")
            event.trace = self
            if self.entrypoint is None and isinstance(event, BasicBlockEntry):
                self.entrypoint = event
        self._functions_by_idx: Optional[Dict[int, Function]] = None
        self._basic_blocks_by_idx: Optional[Dict[int, BasicBlock]] = None
        self.inputstr: bytes = inputstr
        self._cfg: Optional[DiGraph[BasicBlockEntry]] = None

    def consumed_bytes(self) -> Iterator[Tuple[int, bytes]]:
        """Yields the sequence of (byte offset, byte sequence) pairs as they were read in the trace"""
        for bb in self.events:
            if isinstance(bb, BasicBlockEntry):
                yield from ((offset, self.inputstr[offset : offset + 1]) for offset in bb.consumed)

    def __len__(self):
        return len(self.events)

    def __iter__(self) -> Iterable[TraceEvent]:
        return iter(self.events)

    @property
    def functions(self) -> Iterable[Function]:
        if self._functions_by_idx is None:
            _ = self.basic_blocks  # this populates the function mapping
        return self._functions_by_idx.values()  # type: ignore

    @property
    def basic_blocks(self) -> Iterable[BasicBlock]:
        if self._basic_blocks_by_idx is None:
            self._basic_blocks_by_idx = {}
            self._functions_by_idx = {}
            last_bb: Optional[BasicBlock] = None
            for event in self.events:
                if isinstance(event, BasicBlockEntry):
                    if event.function_index in self._functions_by_idx:
                        function = self._functions_by_idx[event.function_index]
                    else:
                        function = Function(name=event.function_name, function_index=event.function_index)
                        self._functions_by_idx[event.function_index] = function
                    if event.global_index in self._basic_blocks_by_idx:
                        new_bb = self._basic_blocks_by_idx[event.global_index]
                    else:
                        new_bb = BasicBlock(function=function, index_in_function=event.bb_index)
                        self._basic_blocks_by_idx[event.global_index] = new_bb
                    if last_bb is not None:
                        new_bb.predecessors.add(last_bb)
                        last_bb.children.add(new_bb)
                    last_bb = new_bb
        return self._basic_blocks_by_idx.values()

    def get_basic_block(self, entry: BasicBlockEntry) -> BasicBlock:
        _ = self.basic_blocks
        return self._basic_blocks_by_idx[entry.global_index]  # type: ignore

    def __getitem__(self, uid: int) -> TraceEvent:
        return self.events_by_uid[uid]

    def __contains__(self, uid: int):
        return uid in self.events_by_uid

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

    @staticmethod
    def parse(trace_file: IO, input_file: Optional[BinaryIO] = None) -> "PolyTrackerTrace":
        try:
            data = json.load(trace_file)
        except json.decoder.JSONDecodeError as de:
            raise ValueError(f"Error parsing PolyTracker JSON file {trace_file.name}", de)
        if "trace" not in data:
            raise ValueError(f"File {trace_file.name} was not recorded with POLYTRACE=1!")
        trace = data["trace"]

        events = [TraceEvent.parse(event) for event in tqdm(trace, leave=False, unit=" events", desc="loading trace")]

        if "inputstr" not in data:
            if input_file is None:
                raise ValueError(
                    "Either the input trace must include the 'inputstr' field, or an `input_file` argument" "must be provided"
                )
            else:
                inputstr: bytes = input_file.read()
        else:
            inputstr = bytes(trace["inputstr"])

        return PolyTrackerTrace(events=events, inputstr=inputstr)
