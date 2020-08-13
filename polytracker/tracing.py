import json
from abc import ABCMeta
from typing import Any, BinaryIO, Callable, Dict, IO, Iterable, List, Optional, Set, Type, Union

from tqdm import tqdm

from polytracker.cfg import DiGraph


EVENTS_BY_TYPE: Dict[str, Callable[[Any], 'TraceEvent']] = {}


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

    def is_loop_entry(self, trace: 'PolyTrackerTrace') -> bool:
        predecessors = set(p for p in self.predecessors if self.function == p.function)
        if len(predecessors) < 2:
            return False
        dominators = set(trace.cfg.dominator_forest.predecessors(self))
        # we are a loop entry if we have one predecessor that dominates us and another that doesn't
        if not any(p in predecessors for p in dominators):
            return False
        return any(p not in dominators for p in predecessors)

    def is_conditional(self, trace: 'PolyTrackerTrace') -> bool:
        # we are a conditional if we have at least two children in the same function and we are not a loop entry
        return sum(1 for c in self.children if c.function == self.function) >= 2 and not self.is_loop_entry(trace)

    def __hash__(self):
        return hash((self.function, self.index_in_function))

    def __eq__(self, other):
        return isinstance(other, BasicBlock) and other.function == self.function and \
               self.index_in_function == other.index_in_function

    def __str__(self):
        return f"{self.function!s}@{self.index_in_function}"


class FunctionInvocation:
    def __init__(self, function: Function, call: 'FunctionCall', ret: 'FunctionReturn'):
        self.function: Function = function
        self.call: FunctionCall = call
        self.ret: FunctionReturn = ret


class TraceEventMeta(ABCMeta):
    def __init__(cls: Type['TraceEvent'], name, bases, clsdict):
        if len(cls.mro()) > 2 and not cls.__abstractmethods__:
            if cls.event_type in EVENTS_BY_TYPE:
                raise ValueError(f"Class {cls.__name__} cannot register with event type {cls.event_type} because "
                                 f"that type is already used by {EVENTS_BY_TYPE[cls.event_type].__name__}")
            EVENTS_BY_TYPE[cls.event_type] = cls
        super().__init__(name, bases, clsdict)


class TraceEvent(metaclass=TraceEventMeta):
    event_type: str = 'TraceEvent'

    def __init__(self, uid: int, previous_uid: Optional[int]):
        self.uid: int = uid
        self.previous_uid: Optional[int] = previous_uid
        self._trace: Optional[PolyTrackerTrace] = None

    @property
    def trace(self) -> Optional['PolyTrackerTrace']:
        return self._trace

    @trace.setter
    def trace(self, pttrace: 'PolyTrackerTrace'):
        if self._trace is not None:
            raise ValueError(f"Cannot assign event {self} to trace {pttrace} because "
                             "it is already assigned to trace {self._trace}")
        self._trace = pttrace

    def initialized(self):
        """Callback for when all events in a PolyTrackerTrace are ready for use"""
        pass

    @property
    def previous(self) -> Optional['TraceEvent']:
        if self.previous_uid is None:
            return None
        else:
            return self.trace[self.previous_uid]

    @staticmethod
    def parse(json_obj: Dict[str, Any]) -> 'TraceEvent':
        if 'type' not in json_obj:
            raise KeyError("The JSON object must contain a key \"type\" for the event type")
        elif json_obj['type'] not in EVENTS_BY_TYPE:
            raise ValueError(f"Unknown event type {json_obj['type']}; valid types are {list(EVENTS_BY_TYPE.keys())!r}")
        event_type: str = json_obj['type']
        arguments: Dict[str, Any] = json_obj.copy()
        del arguments['type']
        return EVENTS_BY_TYPE[event_type](**arguments)

    def __eq__(self, other):
        return isinstance(other, TraceEvent) and other.uid == self.uid

    def __lt__(self, other):
        return self.uid < other.uid

    def __hash__(self):
        return self.uid


class FunctionCall(TraceEvent):
    event_type = 'FunctionCall'

    def __init__(self, uid: int, previous_uid: Optional[int], name: str):
        super().__init__(uid, previous_uid)
        self.name = name

    @property
    def caller(self) -> 'BasicBlockEntry':
        prev = self.previous
        if not isinstance(prev, BasicBlockEntry):
            raise TypeError(f"The previous event to {self} was expected to be a BasicBlockEntry but was in fact {prev}")
        return prev

    def __repr__(self):
        return f"{self.__class__.__name__}({self.uid!r}, {self.previous_uid!r}, {self.name!r})"


class BasicBlockEntry(TraceEvent):
    event_type = 'BasicBlockEntry'

    def __init__(
            self,
            uid: int,
            previous_uid: Optional[int],
            name: str,
            function: str,
            function_index: int,
            bb_index: int,
            global_index: int,
            consumed: List[int]
    ):
        super().__init__(uid, previous_uid)
        self.name: str = name
        self.function: str = function
        self.function_index: int = function_index
        self.bb_index: int = bb_index
        self.global_index: int = global_index
        self.consumed: List[int] = sorted(consumed)
        self._entry_count: Optional[int] = None
        self._children: List[BasicBlockEntry] = []
        self._children_set: bool = False
        self._predecessors: List[BasicBlockEntry] = []

    def remove(self) -> bool:
        if len(self.predecessors) > 1:
            return False
        elif len(self.children) > 1:
            return False
        elif len(self.predecessors) == 1 and len(self.children) == 1 and isinstance(self.previous, BasicBlockEntry):
            self.predecessors[0]._children.remove(self)
            self.predecessors[0]._children.append(self.children[0])
            self.children[0]._predecessors.remove(self)
            self.children[0]._predecessors.append(self.predecessors[0])
            self.children[0].consumed = list(set(self.children[0].consumed + self.consumed))
            self.children[0].previous_uid = self.previous_uid
        elif len(self.children) == 1:
            self.children[0]._predecessors.remove(self)
            self.children[0].previous_uid = None
            self.children[0].consumed = list(set(self.children[0].consumed + self.consumed))
        elif len(self.predecessors) == 1:
            self.predecessors[0]._children.remove(self)
            self.predecessors[0].consumed = list(set(self.predecessors[0].consumed + self.consumed))
        elif self.consumed:
            return False
        return True

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
                yield self.trace.inputstr[start_offset:last_offset+1]
                start_offset = last_offset = offset
            else:
                # this is a contiguous byte sequence, so update its end
                last_offset = offset
        if start_offset is not None:
            yield self.trace.inputstr[start_offset:last_offset+1]

    @property
    def children(self) -> List['BasicBlockEntry']:
        if not self._children_set:
            for event in self.trace.events:
                if isinstance(event, BasicBlockEntry):
                    event._set_children()
        return self._children

    @property
    def predecessors(self) -> List['BasicBlockEntry']:
        if not self._children_set:
            _ = self.children
        return self._predecessors

    def _set_children(self):
        self._children_set = True
        prev = self.previous
        if isinstance(prev, BasicBlockEntry):
            prev._children.append(self)
            self._predecessors.append(prev)
        elif isinstance(prev, FunctionReturn):
            try:
                caller = prev.function_call.caller
            except (ValueError, TypeError):
                # This just means there were not matching function calls,
                # which is likely due to an instrumentation error
                # (this can sometimes happen on the first function in the trace)
                # deal with it by connecting the previous basic block to us, if one exists
                while prev is not None and not isinstance(prev, BasicBlockEntry):
                    prev = prev.previous
                if isinstance(prev, BasicBlockEntry):
                    prev._children.append(self)
                    self._predecessors.append(prev)
                return
            if caller != self:
                caller._children.append(self)
                self._predecessors.append(caller)
        elif isinstance(prev, FunctionCall):
            if prev.previous is not None and isinstance(prev.previous, BasicBlockEntry):
                prev.caller._children.append(self)
                self._predecessors.append(prev.caller)

    @property
    def entry_count(self) -> int:
        if self._entry_count is None:
            event = self.previous
            self._entry_count = 0
            while event is not None:
                if isinstance(event, BasicBlockEntry) and event.basic_block == self.basic_block:
                    self._entry_count += 1
                elif isinstance(event, FunctionCall):
                    break
                event = event.previous
        return self._entry_count

    @property
    def basic_block(self) -> BasicBlock:
        return self.trace.get_basic_block(self)

    def __str__(self):
        return f"{self.basic_block!s}#{self.entry_count}"


class FunctionReturn(TraceEvent):
    event_type = 'FunctionReturn'

    def __init__(self, uid: int, previous_uid: Optional[int], name: str, returning_to_uid: Optional[int]):
        super().__init__(uid, previous_uid)
        self.function_name: str = name
        self.returning_to_uid: Optional[int] = returning_to_uid
        self._returning_to: Optional[BasicBlockEntry] = None
        self._function_call: Optional[Union[FunctionCall, ValueError]] = None

    def __repr__(self):
        return f"{self.__class__.__name__}({self.uid!r}, {self.previous_uid!r}, {self.function_name!r}, "\
               f"{self.returning_to_uid!r})"

    @property
    def returning_to(self) -> Optional[BasicBlockEntry]:
        if self._returning_to is None:
            if self.returning_to_uid is None:
                return None
            ret = self.trace[self.returning_to_uid]
            if not isinstance(ret, BasicBlockEntry):
                raise ValueError(f"Expected function return {self} to return to a basic block entry event, "
                                 f"but instead it returned to {ret}!")
            self._returning_to = ret
        return self._returning_to

    @property
    def function_call(self) -> FunctionCall:
        if self._function_call is None:
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
                prev = prev.previous
            if isinstance(prev, FunctionCall):
                self._function_call = prev
            else:
                self._function_call = ValueError(f"Could not find the function call associated with return {self}")
        if isinstance(self._function_call, ValueError):
            raise self._function_call
        return self._function_call


class PolyTrackerTrace:
    def __init__(self, events: List[TraceEvent], inputstr: bytes):
        self.events: List[TraceEvent] = sorted(events)
        self.events_by_uid: Dict[int, TraceEvent] = {
            event.uid: event for event in events
        }
        self.entrypoint: Optional[BasicBlockEntry] = None
        for event in tqdm(self.events, unit=" events", leave=False, desc="initializing trace events"):
            if event.trace is not None:
                raise ValueError(f"Event {event} is already associated with trace {event.trace}")
            event.trace = self
            if self.entrypoint is None and isinstance(event, BasicBlockEntry):
                self.entrypoint = event
        self._functions_by_idx: Optional[Dict[int, Function]] = None
        self._basic_blocks_by_idx: Optional[Dict[int, BasicBlock]] = None
        self.inputstr: bytes = inputstr
        self._cfg: Optional[DiGraph[BasicBlockEntry]] = None

    def __len__(self):
        return len(self.events)

    def __iter__(self) -> Iterable[TraceEvent]:
        return iter(self.events)

    def simplify(self) -> int:
        reductions = 0
        # first, remove trivial basic blocks (that have at most once predecessor and one successor)
        to_remove = set()
        for event in self.events:
            if isinstance(event, BasicBlockEntry):
                if len(event.basic_block.predecessors) <= 1 and len(event.basic_block.children) <= 1:
                    if not event.remove():
                        continue
                    to_remove.add(event)
                    reductions += 1

        self.events = [event for event in self.events if event not in to_remove]

        if reductions > 0:
            # invalidate our caches
            self._cfg = None

        return reductions

    @property
    def functions(self) -> Iterable[Function]:
        if self._functions_by_idx is None:
            _ = self.basic_blocks  # this populates the function mapping
        return self._functions_by_idx.values()

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
                        function = Function(name=event.function, function_index=event.function_index)
                        self._functions_by_idx[event.function_index] = function
                    if event.global_index in self._basic_blocks_by_idx:
                        new_bb = self._basic_blocks_by_idx[event.global_index]
                    else:
                        new_bb = BasicBlock(
                            function=function,
                            index_in_function=event.bb_index
                        )
                        self._basic_blocks_by_idx[event.global_index] = new_bb
                    if last_bb is not None:
                        new_bb.predecessors.add(last_bb)
                        last_bb.children.add(new_bb)
                    last_bb = new_bb
        return self._basic_blocks_by_idx.values()

    def get_basic_block(self, entry: BasicBlockEntry) -> BasicBlock:
        _ = self.basic_blocks
        return self._basic_blocks_by_idx[entry.global_index]

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

        events = [TraceEvent.parse(event) for event in trace]

        if 'inputstr' not in data:
            if input_file is None:
                raise ValueError("Either the input trace must include the 'inputstr' field, or an `input_file` argument"
                                 "must be provided")
            else:
                inputstr: bytes = input_file.read()
        else:
            inputstr: bytes = bytes(trace['inputstr'])

        return PolyTrackerTrace(events=events, inputstr=inputstr)
