from abc import ABC, abstractmethod
from enum import IntFlag
from typing import (
    cast,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Union,
)
import os

from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from tqdm import tqdm

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


class Function:
    def __init__(self, name: str, function_index: int):
        self.name: str = name
        self.basic_blocks: List[BasicBlock] = []
        self.function_index = function_index

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


class FunctionInvocation:
    def __init__(self, function: Function, call: "FunctionCall", ret: "FunctionReturn"):
        self.function: Function = function
        self.call: FunctionCall = call
        self.ret: FunctionReturn = ret


class TraceEvent:
    def __init__(
        self,
        uid: int,
        previous_uid: Optional[int] = None,
        next_uid: Optional[int] = None,
    ):
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
                f"The trace for event {self!r} has not been set!"
                "Did you call `.trace` before the entire trace was loaded?"
            )
        return self._trace

    @trace.setter
    def trace(self, pttrace: "PolyTrackerTrace"):
        if self._trace is not None:
            raise ValueError(
                f"Cannot assign event {self} to trace {pttrace} because it is already assigned to trace {self._trace}"
            )
        self._trace = pttrace

    @property
    def previous_event(self) -> Optional["TraceEvent"]:
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

    def __eq__(self, other):
        return isinstance(other, TraceEvent) and other.uid == self.uid

    def __lt__(self, other):
        return self.uid < other.uid

    def __hash__(self):
        return self.uid


class FunctionCall(TraceEvent):
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
        self.consumed: List[int] = sorted(consumed)
        self.called_function: Optional[FunctionCall] = None
        """The function this basic block calls"""
        self.types: List[str] = list(types)
        self.bb_type: BasicBlockType = cast(BasicBlockType, BasicBlockType.UNKNOWN)
        for ty in types:
            bb_type = BasicBlockType.get(ty.upper())
            if bb_type is None:
                raise ValueError(
                    f"Unknown basic block type: {ty!r} in basic block entry {uid}"
                )
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
        prev_event = self.previous_event
        if BasicBlockType.FUNCTION_ENTRY in self.bb_type and isinstance(prev_event, FunctionCall):  # type: ignore
            prev_event.entrypoint = self
        if isinstance(prev_event, BasicBlockEntry):
            prev_event.children.append(self)

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
                self._function_call = ValueError(
                    f"Could not find the function call associated with return {self}"
                )
        if isinstance(self._function_call, ValueError):
            raise self._function_call
        return self._function_call  # type: ignore


class PolyTrackerTrace(ABC):
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


class InMemoryPolyTrackerTrace(PolyTrackerTrace):
    def __init__(self, events: List[TraceEvent], inputstr: bytes):
        self.events: List[TraceEvent] = sorted(events)
        self.events_by_uid: Dict[int, TraceEvent] = {
            event.uid: event
            for event in tqdm(
                events, leave=False, unit=" events", desc="building UID map"
            )
        }
        print(f"events {self.events}")
        self.entrypoint: Optional[BasicBlockEntry] = None
        for event in tqdm(
            self.events, unit=" events", leave=False, desc="initializing trace events"
        ):
            if event.has_trace:
                raise ValueError(
                    f"Event {event} is already associated with trace {event.trace}"
                )
            event.trace = self
            if self.entrypoint is None and isinstance(event, BasicBlockEntry):
                self.entrypoint = event
        self._functions_by_idx: Optional[Dict[int, Function]] = None
        self._basic_blocks_by_idx: Optional[Dict[int, BasicBlock]] = None
        self.inputstr: bytes = inputstr

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
                        function = Function(
                            name=event.function_name,
                            function_index=event.function_index,
                        )
                        self._functions_by_idx[event.function_index] = function
                    if event.global_index in self._basic_blocks_by_idx:
                        new_bb = self._basic_blocks_by_idx[event.global_index]
                    else:
                        new_bb = BasicBlock(
                            function=function, index_in_function=event.bb_index
                        )
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

    @staticmethod
    def parse(trace_file: str, input_file: str) -> "PolyTrackerTrace":
        trace_file = os.path.realpath(trace_file)
        events = trace_to_dict(trace_file, input_file)
        if input_file is None:
            raise ValueError("`input_file` argument" "must be provided")
        with open(input_file, "rb") as f:
            input_str = f.read()
        assert input_str is not None

        return PolyTrackerTrace(events=events, inputstr=input_str)


def trace_to_dict(db_path: str, input_file: str) -> List[TraceEvent]:
    engine = create_engine(f"sqlite:///{db_path}")
    session_maker = sessionmaker(bind=engine)
    session = session_maker()

    # Find input_id
    input_id = None
    for some_input in session.query(InputItem):
        test: InputItem = some_input
        if input_file in some_input.path:
            input_id = test.id

    if input_id is None:
        print(f"Error! Could not find input id for {db_path}")
        exit(1)

    print(f"input_id: {input_id}")

    funcs = {}
    for func_item in session.query(FunctionItem).all():
        item: FunctionItem = func_item
        funcs[item.id] = item.name

    print(funcs)

    trace_events = []

    for instance in session.query(FunctionRetItem).filter(
        FunctionRetItem.input_id == input_id
    ):
        trace_events.append(gen_func_ret(instance, funcs))
        print(instance)
    for instance in session.query(FunctionCallItem).filter(
        FunctionCallItem.input_id == input_id
    ):
        trace_events.append(gen_func_call(instance, funcs))
        print(instance)
    for instance in session.query(BlockInstanceItem).filter(
        BlockInstanceItem.input_id == input_id
    ):
        trace_events.append(gen_block_entry(instance, funcs, input_id, session))
        print(instance)

    # TODO (Evan) this is super bad, but to fit in with the rest of the code, I needed to know the minimum
    # and maximum event_ids so I could prevent indexing into a dict with bad key.
    # The minimum is easy, its just 1. So what I do here is I find the (index, event_id) with highest event id
    # Then manually change its next_uid to None
    highest_event = 1
    index = 0
    for i, event in enumerate(trace_events):
        if event.uid > highest_event:
            highest_event = event.uid
            index = i
    trace_events[index].next_uid = None
    print(trace_events)
    return trace_events
