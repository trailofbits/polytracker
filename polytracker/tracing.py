"""A module defining the abstract classes used for represenging a program trace.

The implementation of these classes that actually loads the SQLite database emitted by the PolyTracker instrumentation
is in :mod:`polytracker.database`. For example, :class:`polytracker.database.DBProgramTrace` is mapped to
:class:`polytracker.PolyTrackerTrace`.

"""

from abc import ABC, abstractmethod
from argparse import ArgumentParser, Namespace, REMAINDER
from collections import defaultdict
from enum import IntFlag
import itertools
from os.path import commonpath
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
    Tuple,
    Union,
)
import weakref

from cxxfilt import demangle
from tqdm import tqdm

from .cfg import DiGraph
from .inputs import Input, InputProperties
from .plugins import Command, Subcommand
from .repl import PolyTrackerREPL
from .taint_forest import TaintForest, TaintForestNode


class BasicBlockType(IntFlag):
    """
    Basic block types

    This should be kept in parity with the enum in
    `/polytracker/include/polytracker/basic_block_types.h
    <https://github.com/trailofbits/polytracker/blob/master/polytracker/include/polytracker/basic_block_types.h>`_

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


class ByteAccessType(IntFlag):
    """Bitfield enum defining the context in which taints were accessed.

    This should be kept in parity with the enum in
    `/polytracker/include/polytracker/output.h
    <https://github.com/trailofbits/polytracker/blob/master/polytracker/include/polytracker/output.h>`_

    """

    UNKNOWN_ACCESS = 0
    INPUT_ACCESS = 1
    CMP_ACCESS = 2
    READ_ACCESS = 4


class TaintedRegion:
    """Base class representing a tainted region of code"""

    def __init__(self, source: Input, offset: int, length: int):
        """Initializes a tainted region.

        Args:
            source: The input that tainted this region.
            offset: The byte offset of the input in which this region starts.
            length: The number of bytes in this region.

        """
        self.source: Input = source
        self.offset: int = offset
        self.length: int = length

    @property
    def value(self) -> bytes:
        """The actual bytes from the input file associated with this region.

        Raises:
            ValueError: If the input did not have its content stored to the database (*e.g.*, if the instrumented binary
                        was run with ``POLYSAVEINPUT=0``) and :attr:`self.source.path <polytracker.inputs.Input.path>`
                        does not exist.

        """
        return self.source.content[self.offset: self.offset + self.length]

    def __getitem__(self, index_or_slice: Union[int, slice]) -> "TaintedRegion":
        """Gets a :class:`ByteOffset` or sliced :class:`TaintedRegion` from this region"""
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
            return TaintedRegion(source=self.source, offset=self.offset + start, length=stop - start)
        elif index_or_slice < 0 or index_or_slice >= self.length:
            raise IndexError(index_or_slice)
        else:
            return ByteOffset(source=self.source, offset=self.offset + index_or_slice)

    def __bytes__(self):
        """Equivalent to :attr:`self.value`"""
        return self.value

    def __hash__(self):
        return hash((self.source, self.offset))

    def __eq__(self, other):
        return (
                isinstance(other, TaintedRegion)
                and self.source == other.source
                and self.offset == other.offset
                and self.length == other.length
        )

    def __lt__(self, other):
        return isinstance(other, TaintedRegion) and (self.source.uid, self.offset, self.length) < (
            other.source.uid,
            other.offset,
            other.length,
        )


class ByteOffset(TaintedRegion):
    """A :class:`TaintedRegion` of length 1."""

    def __init__(self, source: Input, offset: int):
        super().__init__(source=source, offset=offset, length=1)


class TaintDiff:
    """A diff of two sets of taints."""

    def __init__(self, taints1: "Taints", taints2: "Taints"):
        """Initializes a taint diff.

        Args:
            taints1: the first set of taints to compare.
            taints2: the second set of taints to compare.

        """
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
        """Returns a list of all of the tainted byte offsets only in the first set of taints."""
        self._diff()
        return self._only_in_first  # type: ignore

    @property
    def regions_only_in_first(self) -> Iterator[TaintedRegion]:
        """Returns a list of all of the tainted byte regions only in the first set of taints."""
        yield from Taints.to_regions(self.bytes_only_in_first, is_sorted=True)

    @property
    def bytes_only_in_second(self) -> List[ByteOffset]:
        """Returns a list of all of the tainted byte offsets only in the second set of taints."""
        self._diff()
        return self._only_in_second  # type: ignore

    @property
    def regions_only_in_second(self) -> Iterator[TaintedRegion]:
        """Returns a list of all of the tainted byte regions only in the second set of taints."""
        yield from Taints.to_regions(self.bytes_only_in_second, is_sorted=True)

    def __bool__(self):
        """Equivalent to ``bool(self.bytes_only_in_first) or bool(self.bytes_only_in_second)``"""
        return bool(self.bytes_only_in_first) or bool(self.bytes_only_in_second)

    def __eq__(self, other):
        return isinstance(other, TaintDiff) and self.taints1 == other.taints1 and self.taints2 == other.taints2


class Taints:
    """A class for representing a collection of tainted regions"""

    def __init__(self, byte_offsets: Iterable[ByteOffset]):
        """Initializes a taint collection.

        Args:
            byte_offsets: The tainted byte offsets to include in this collection.

        """
        offsets_by_source: Dict[Input, Set[ByteOffset]] = defaultdict(set)
        for offset in byte_offsets:
            offsets_by_source[offset.source].add(offset)
        self._offsets_by_source: Dict[Input, List[ByteOffset]] = {
            source: sorted(offsets) for source, offsets in offsets_by_source.items()
        }

    def sources(self) -> Set[Input]:
        """Returns the set of sources from which this collection of taints originates."""
        return set(self._offsets_by_source.keys())

    def from_source(self, source: Input) -> "Taints":
        """Returns a subset of the taints in this collection that come from a specific source"""
        return Taints(self._offsets_by_source.get(source, ()))

    def regions(self) -> Iterator[TaintedRegion]:
        """Iterates over all of the contiguous regions of taint in this collection.

        The regions are yielded in increasing order of offset.

        .. caution::

            The regions *will not* be grouped by source! Regions from different sources will be intermixed. Use
            :meth:`Taints.from_source` if you want to differentiate regions by source.

        This is equivalent to::

            return Taints.to_regions(self, is_sorted=True)

        """
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
        """Yields all matching tainted subsequences in this collection.

        Args:
            byte_sequence: The individual byte (``int``), string (``str``), or byte sequence (``bytes``) to find

        Returns:
            All matching regions in this collection.

        """
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
                    yield region[offset: offset + len(byte_sequence)]
                else:
                    break

    def diff(self, other: "Taints") -> TaintDiff:
        """Diffs this taint collection with another collection.

        This is equivalent to::

            TaintDiff(self, other)

        Args:
            other: The other collection against which to compare.

        Returns:
            The diff of the two taint collections.

        """
        return TaintDiff(self, other)

    def __contains__(self, byte_sequence: Union[int, str, bytes]):
        """Checks whether this taint collection contains at least one matching byte sequence.

        This is equivalent to::

            try:
                next(iter(self.find(byte_sequence)))
                return True
            except StopIteration:
                return False

        """
        try:
            next(iter(self.find(byte_sequence)))
            return True
        except StopIteration:
            return False

    def __len__(self):
        """The total number of tainted bytes in this collection."""
        return sum(map(len, self._offsets_by_source.values()))

    def __iter__(self) -> Iterator[ByteOffset]:
        """Iterates over all of the individual byte offsets in this collection, grouped by source.

        .. note::

            The byte offsets are guaranteed to be yielded in increasing order of byte offset per source, but the order
            of sources is arbitrary.

        """
        for offsets in self._offsets_by_source.values():
            yield from offsets

    def __bool__(self):
        """Returns whether this taint collection has at least one tainted byte.

        This is equivalent to::

            bool(len(self))

        """
        return bool(len(self))


class Function:
    """A class representing a function inside of an instrumented program.

    .. note::

        This is a static function instance, *not* a function that is observed during a runtime trace.

        For runtime trace events, see :class:`FunctionInvocation`, :class:`FunctionEntry`, and :class:`FunctionReturn`.

    """

    def __init__(self, name: str, function_index: int):
        """Initializes a Function.

        Args:
            name: The name of the function
            function_index: A unique ID for the function.

        """
        self.name: str = name
        self.basic_blocks: List[BasicBlock] = []
        """A list of :class:`basic blocks <BasicBlock>` contained in this function."""
        self.function_index: int = function_index

    @property
    def demangled_name(self) -> str:
        """The demangled name of this function."""
        return demangle(self.name)

    @abstractmethod
    def taints(self) -> Taints:
        """Returns all taints operated on by this function across all invocations of the function in a trace."""
        raise NotImplementedError()

    @abstractmethod
    def calls_to(self) -> Set["Function"]:
        """Returns the set of functions to which this function calls, potentially including itself (if recursive)."""
        raise NotImplementedError()

    @abstractmethod
    def called_from(self) -> Set["Function"]:
        """Returns the set of functions from which this function is called, potentially including itself
        (if recursive)"""
        raise NotImplementedError()

    def __hash__(self):
        return self.function_index

    def __eq__(self, other):
        return isinstance(other, Function) and self.function_index == other.function_index

    def __str__(self):
        return self.name


class BasicBlock:
    """A class representing a basic block in an instrumented program.

    .. note::

        This is a static basic block instance, *not* a basic block that is observed during a runtime trace.

        For runtime trace events, see :class:`BasicBlockEntry`.

    """

    def __init__(self, function: Function, index_in_function: int):
        """Initializes a basic block.

        .. caution::

            This constructor will call::

                function.basic_blocks.append(self)

        Args:
            function: The function in which this basic block is contained.
            index_in_function: An ID for the basic block, unique among all basic blocks in :attr:`function`.

        """
        self.function: Function = function
        self.index_in_function: int = index_in_function
        self.children: Set[BasicBlock] = set()
        """All basic blocks to which this block can jump."""
        self.predecessors: Set[BasicBlock] = set()
        """All basic blocks that precede this basic block."""
        function.basic_blocks.append(self)

    @abstractmethod
    def entries(self) -> Iterator["BasicBlockEntry"]:
        """Yields all trace events associated with entering this basic block."""
        raise NotImplementedError()

    @abstractmethod
    def taints(self) -> Taints:
        """Returns the set of all taints operated on by this basic block across an entire trace."""
        raise NotImplementedError()

    def is_loop_entry(self, trace: "ProgramTrace") -> bool:
        """Calculates whether this basic block is an entry to a loop."""
        predecessors = set(p for p in self.predecessors if self.function == p.function)
        if len(predecessors) < 2:
            return False
        dominators = set(trace.cfg.dominator_forest.predecessors(self))
        # we are a loop entry if we have one predecessor that dominates us and another that doesn't
        if not any(p in predecessors for p in dominators):
            return False
        return any(p not in dominators for p in predecessors)

    def is_conditional(self, trace: "ProgramTrace") -> bool:
        """Returns whether this basic block contains a conditional branch."""
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


class TraceEvent:
    """An abstract base class for all trace events.

    .. note::

        This class *should ideally* extend off of :class:`collections.abc.ABC`. The reason why it *does not* is because
        it is extended through multiple inheritance in :mod:`polytracker.database` along with a SQLAlchemy base class,
        and SQLAlchemy does not play well with ``ABCMeta``.

    """

    def __init__(self, uid: int):
        """Initializes a trace event.

        Args:
            uid: An identifier for this event that is unique across the entire trace.
        """
        self.uid: int = uid

    @property
    @abstractmethod
    def basic_block(self) -> BasicBlock:
        """The basic block that was executing during which this event took place."""
        raise NotImplementedError()

    @property
    def function(self) -> Function:
        """The function that was executing during which this event took place."""
        return self.basic_block.function

    @abstractmethod
    def taints(self) -> Taints:
        """The set of taints operated on during this event."""
        raise NotImplementedError()

    @property
    def touched_taint(self) -> bool:
        """Whether or not this event touched taint."""
        return bool(self.taints())

    @property
    @abstractmethod
    def previous_event(self) -> Optional["TraceEvent"]:
        """The previous event in the trace that occurred in the same thread, if one exists.

        For the previous event from *any* thread, see :meth:`TraceEvent.previous_global_event`.

        """
        raise NotImplementedError()

    @property
    @abstractmethod
    def next_event(self) -> Optional["TraceEvent"]:
        """The next event in the trace that occurred in the same thread, if one exists.

        For the next event from *any* thread, see :meth:`TraceEvent.next_global_event`.

        """
        raise NotImplementedError()

    @property
    def next_control_flow_event(self) -> Optional["ControlFlowEvent"]:
        """The next control flow event in the trace that occurred in the same thread, if one exists."""
        next_event = self.next_event
        while next_event is not None:
            if isinstance(next_event, ControlFlowEvent):
                return next_event
            next_event = next_event.next_event
        return None

    @property
    def previous_control_flow_event(self) -> Optional["ControlFlowEvent"]:
        """The previous control flow event in the trace that occurred in the same thread, if one exists."""
        previous_event = self.previous_event
        while previous_event is not None:
            if isinstance(previous_event, ControlFlowEvent):
                return previous_event
            previous_event = previous_event.previous_event
        return None

    @property
    @abstractmethod
    def next_global_event(self) -> Optional["TraceEvent"]:
        """The next event that occurred in the trace, regardless of thread, if one exists."""
        raise NotImplementedError()

    @property
    @abstractmethod
    def previous_global_event(self) -> Optional["TraceEvent"]:
        """The previous event that occurred in the trace, regardless of thread, if one exists."""
        raise NotImplementedError()

    @property
    @abstractmethod
    def function_entry(self) -> Optional["FunctionEntry"]:
        """The function entry event associated with the stack frame in which this event occurred, if one exists."""
        raise NotImplementedError()

    def __eq__(self, other):
        return isinstance(other, TraceEvent) and other.uid == self.uid

    def __lt__(self, other):
        return self.uid < other.uid

    def __hash__(self):
        return self.uid


class ControlFlowEvent(TraceEvent):
    """An abstract base class for events that have to do with control flow."""

    pass


class FunctionEvent(ControlFlowEvent):
    pass


class CallUninst(FunctionEvent):
    """ A trace event associated with calling an uninstrumented function
    """

    # TODO (Carson) don't rely on database
    @property
    def basic_block(self) -> BasicBlock:
        """The basic block that called `return`. For the return site of the function, use `self.returning_to`"""
        return self.basic_block


class CallIndirect(FunctionEvent):
    """ A trace event associated with making an indirect call (ex: function pointers)
    """

    def __repr__(self):
        return f"{self.__class__.__name__}({self.uid!r})"

    @property
    def basic_block(self) -> BasicBlock:
        """The basic block that called `return`. For the return site of the function, use `self.returning_to`"""
        return self.basic_block


class FunctionEntry(FunctionEvent):
    """An abstract class representing the entry into a function."""

    @property
    def caller(self) -> Optional["BasicBlockEntry"]:
        """The :class:`BasicBlockEntry` event associated with the basic block that called this function."""
        prev = self.previous_control_flow_event
        while prev is not None:
            if isinstance(prev, BasicBlockEntry):
                return prev
            elif isinstance(prev, FunctionReturn):
                prev = prev.function_entry
                if prev is None:
                    break
            prev = prev.previous_control_flow_event
        return None

    @property
    def entrypoint(self) -> Optional["BasicBlockEntry"]:
        """Returns the :class:`BasicBlockEntry` event associated with the first basic block entered in this function."""
        next_event = self.next_control_flow_event
        if isinstance(next_event, BasicBlockEntry):
            if next_event.function_entry != self:
                raise ValueError(f"Unexpected basic block: {next_event}")
            return next_event
        return None

    @property
    def basic_block(self) -> BasicBlock:
        """Returns the entrypoint of this function.

        For the basic block that called into this function, use :meth:`FunctionEntry.caller`

        """
        if self.entrypoint is None:
            raise ValueError(f"Unable to determine the function entrypoint for {self!r}")
        return self.entrypoint.basic_block

    @property
    def function(self) -> Function:
        """Returns the function that was called"""
        if self.entrypoint is None:
            raise ValueError(f"Unable to determine the function entrypoint for {self!r}")
        return self.entrypoint.function

    @property
    @abstractmethod
    def function_return(self) -> Optional["FunctionReturn"]:
        """The :class:`FunctionReturn` event that returned from this function."""
        raise NotImplementedError()

    def __repr__(self):
        return f"{self.__class__.__name__}({self.uid!r}, {self.function.name!r})"


class TaintAccess:
    """An abstract class for representing a taint access event."""

    def __init__(self, access_id: int, event: TraceEvent, label: int, access_type: ByteAccessType):
        """Initializes a taint access.

        Args:
            access_id: A unique, incrementally assigned identifier for this access.
            event: The trace event associated with this access.
            label: The taint label accessed.
            access_type: The type of access.
        """
        self.access_id: int = access_id
        self.event: TraceEvent = event
        self.label: int = label
        self.access_type: ByteAccessType = access_type

    def taints(self) -> Taints:
        """Returns the collection of taints associated with this access"""
        raise NotImplementedError()

    def __lt__(self, other):
        return hasattr(other, "access_id") and self.access_id < other.access_id

    def __hash__(self):
        return self.access_id

    def __eq__(self, other):
        return isinstance(other, TaintAccess) and self.access_id == other.access_id

    def __repr__(self):
        return f"{self.__class__.__name__}({self.access_id!r}, {self.event!r}, {self.label}, {self.access_type!r})"


class TaintOutput:
    """An abstract class for representing tainted bytes written to an output (file, network socket, etc)."""

    def __init__(self, source: Input, output_offset: int, label: int):
        """
        Args:
            output_offset: offset within the output file
            label: The taint label of the output
        """
        self.source: Input = source
        self.offset: int = output_offset
        self.label: int = label

    @abstractmethod
    def taints(self) -> Taints:
        raise NotImplementedError()

    def __lt__(self, other):
        return hasattr(other, "offset") and self.offset < other.offset

    def __hash__(self):
        return {self.offset, self.label}

    def __eq__(self, other):
        return isinstance(other, TaintOutput) and self.offset == other.offset

    def __repr__(self):
        return f"{self.__class__.__name__}(Offset: {self.offset!r}, Taint label: {self.label!r})"


class TaintedChunk:
    """An abstract class for representing tainted input chunks."""

    def __init__(self, start_offset: int, end_offset: int):
        self.start_offset: int = start_offset
        self.end_offset: int = end_offset

    def __repr__(self):
        return f"{self.__class__.__name__}({self.start_offset!r}, {self.end_offset!r})"


class BasicBlockEntry(ControlFlowEvent):
    """A trace event associated with entering a basic block."""

    def entry_count(self) -> int:
        """Calculates the number of times this basic block has been entered in the current stack frame."""
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
    def called_function(self) -> Optional["FunctionInvocation"]:
        """The function invocation called from this basic block, or None if this basic block does not call a function"""
        next_event = self.next_control_flow_event
        if isinstance(next_event, FunctionEntry):
            return FunctionInvocation(next_event)
        return None

    def next_basic_block_in_function(self) -> Optional["BasicBlockEntry"]:
        """Finds the next basic block in this function in the trace"""
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

    def next_basic_block_in_function_that_touched_taint(self) -> Optional["BasicBlockEntry"]:
        """Finds the next basic block in this function in the trace that touched taint"""
        bb = self.next_basic_block_in_function()
        while bb is not None and not bb.touched_taint:
            bb = bb.next_basic_block_in_function()
        if bb is not None and bb.touched_taint:
            return bb
        return None

    @property
    def consumed_tokens(self) -> Iterable[bytes]:
        """The collection of tokens consumed during this basic block event.

        This is equivalent to::

            tuple(r.value for r in self.taints().regions())

        """
        return tuple(r.value for r in self.taints().regions())

    def __str__(self):
        return f"{self.basic_block!s}#{self.entry_count()}"


class FunctionReturn(ControlFlowEvent):
    """A trace event associated with returning from a function.

    .. caution::

        The function associated with this event is the function *to which* we are returning, *not* the function
        *from which* we are returning. Use :meth:`FunctionReturn.returning_from` to get the latter.

    """

    def __init__(self, uid: int):
        super().__init__(uid=uid)

    def __repr__(self):
        return f"{self.__class__.__name__}({self.uid!r})"

    @property
    def basic_block(self) -> BasicBlock:
        """The basic block that called `return`. For the return site of the function, use `self.returning_to`"""
        return super().basic_block

    @property
    def returning_to(self) -> Optional[BasicBlockEntry]:
        """The basic block to which the function returned."""
        next_event = self.next_control_flow_event
        if isinstance(next_event, BasicBlockEntry):
            return next_event
        return None

    @property
    def returning_from(self) -> Function:
        """The function from which we are returning."""
        entry = self.function_entry
        if entry is None:
            raise ValueError(f"Unable to determine the function entry object associated with function return {self!r}")
        return entry.basic_block.function


class FunctionInvocation(ControlFlowEvent):
    """A conglomerated trace event representing an entire function invocation.

    This includes associating a :class:`FunctionEntry` with its :class:`FunctionReturn` event, and allows for reasoning
    about any sub-invocations (*i.e.*, other functions called from within this function).

    """

    def __init__(self, function_entry: FunctionEntry):
        """Initializes a function invocation.

        Args:
            function_entry: The function entry event that initiated this invocation.

        """
        super().__init__(function_entry.uid)
        self._function_entry: FunctionEntry = function_entry

    @property
    def basic_block(self) -> BasicBlock:
        """The basic block that called to this function.

        This is equivalent to::

            self.function_entry.basic_block

        """
        return self.function_entry.basic_block

    @property
    def function(self) -> Function:
        return self.function_entry.function

    @property
    def previous_event(self) -> Optional["TraceEvent"]:
        return self.function_entry.previous_event

    @property
    def next_event(self) -> Optional["TraceEvent"]:
        return self.function_entry.next_event

    @property
    def next_global_event(self) -> Optional["TraceEvent"]:
        return self.function_entry.next_global_event

    @property
    def previous_global_event(self) -> Optional[TraceEvent]:
        return self.function_entry.previous_global_event

    @property
    def function_return(self) -> Optional[FunctionReturn]:
        return self.function_entry.function_return

    @property
    def function_entry(self) -> FunctionEntry:
        return self._function_entry

    def calls(self) -> Iterator["FunctionInvocation"]:
        """Yields all of the functions called inside of this invocation, in order"""
        next_event = self.function_entry.next_control_flow_event
        return_event = self.function_return
        while next_event is not None and next_event != return_event:
            if isinstance(next_event, FunctionEntry):
                yield FunctionInvocation(next_event)
                next_event = next_event.function_return
                if next_event is None:
                    return
            next_event = next_event.next_control_flow_event

    def __eq__(self, other):
        return isinstance(other, FunctionInvocation) and other.uid == self.uid

    def __iter__(self) -> Iterator[Union[BasicBlockEntry, "FunctionInvocation"]]:
        """Iterates all of the basic block entries that took place during this function invocation.
        Any functions that are called from this function are yielded as a FunctionInvocation.

        """
        for bb in self.basic_blocks():
            yield bb
            func = bb.called_function
            if func is not None:
                yield func

    def basic_blocks(self) -> Iterator[BasicBlockEntry]:
        """Yields all of the basic blocks executed in this function,
        not including any basic blocks inside called functions.

        """
        entry = self.function_entry.entrypoint
        while entry is not None:
            yield entry
            entry = entry.next_basic_block_in_function()

    def taints(self) -> Taints:
        """Returns all taints operated on by this function or any functions called by this function."""
        if not hasattr(self, "_taints"):
            setattr(self, "_taints", Taints(itertools.chain(*(event.taints() for event in self))))
        return getattr(self, "_taints")

    def __str__(self):
        s = str(self.function)
        caller = self.function_entry.caller
        if caller is not None:
            s = f"{s} called from {caller!s}"
        return_event = self.function_return
        if return_event is not None:
            returning_to = return_event.returning_to
            if returning_to is not None:
                s = f"{s} returning to {returning_to!s}"
        return s


class ProgramTrace(ABC):
    """An abstract class for representing a program trace.

    For a concrete implementation that loads a database produced from a PolyTracker instrumented binary, see
    :class:`polytracker.database.DBProgramTrace`.

    """

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
        """The static functions operated on by the trace."""
        raise NotImplementedError()

    @property
    @abstractmethod
    def basic_blocks(self) -> Iterable[BasicBlock]:
        """The static basic blocks operated on by the trace."""
        raise NotImplementedError()

    @abstractmethod
    def has_event(self, uid: int) -> bool:
        """Returns whether an event with the given ID exists in this trace."""
        raise NotImplementedError()

    @abstractmethod
    def get_event(self, uid: int) -> TraceEvent:
        """Gets a trace event by its ID."""
        raise NotImplementedError()

    @abstractmethod
    def get_function(self, name: str) -> Function:
        """Looks up a function by its name.

        Raises:
            KeyError: if a function of that name was not executed in the trace

        """
        raise NotImplementedError()

    @abstractmethod
    def has_function(self, name: str) -> bool:
        """Returns whether a function of the given name was executed in this trace."""
        raise NotImplementedError()

    @abstractmethod
    def access_sequence(self) -> Iterator[TaintAccess]:
        """Yields the taint accesses in this trace, in order."""
        raise NotImplementedError()

    @property
    @abstractmethod
    def num_accesses(self) -> int:
        """The number of taint accesses in this trace."""
        raise NotImplementedError()

    @property
    @abstractmethod
    def inputs(self) -> Iterable[Input]:
        """The taint sources operated on in this trace."""
        raise NotImplementedError()

    @property
    @abstractmethod
    def outputs(self) -> Optional[Iterable[Input]]:
        """The taint syncs written to in this trace."""
        raise NotImplementedError()

    @property
    @abstractmethod
    def output_taints(self) -> Iterable[TaintOutput]:
        """Iterates over all of the outputs written in the trace"""
        raise NotImplementedError()

    def input_properties(self, source: Input) -> InputProperties:
        first_usages: List[Optional[int]] = [None] * source.size
        file_seeks: List[Tuple[int, int, int]] = []
        last_offset: Optional[int] = None
        for i, taint_access in enumerate(self.access_sequence()):
            for offset in taint_access.taints():
                if not offset.source == source:
                    continue
                if first_usages[offset.offset] is None:
                    first_usages[offset.offset] = i
                if last_offset is not None:
                    if offset.offset < last_offset:
                        file_seeks.append((i - 1, last_offset, offset.offset))
                last_offset = offset.offset
        unused_bytes = [offset for offset, first_used in enumerate(first_usages) if first_used is None]
        out_of_order = [
            previous_offset + 1
            for previous_offset, (previous, first_used) in enumerate(zip(first_usages, first_usages[1:]))
            if previous > first_used  # type: ignore
        ]
        return InputProperties(unused_byte_offsets=unused_bytes, out_of_order_byte_offsets=out_of_order,
                               file_seeks=file_seeks)

    @property
    @abstractmethod
    def taint_forest(self) -> TaintForest:
        """The taint forest associated with this trace."""
        raise NotImplementedError()

    @abstractmethod
    def file_offset(self, node: TaintForestNode) -> ByteOffset:
        """The file offset associated with a taint forest node"""
        raise NotImplementedError()

    def inputs_affecting_control_flow(self) -> Taints:
        """Returns the set of byte offsets that affected control flow"""
        return self.taints((node for node in self.taint_forest.nodes() if node.affected_control_flow))

    def taints(self, labels: Iterable[TaintForestNode]) -> Taints:
        # reverse the labels to reduce the likelihood of reproducing work
        history: Set[TaintForestNode] = set(labels)
        node_stack: List[TaintForestNode] = sorted(list(set(history)), reverse=True)
        taints: Set[ByteOffset] = set()
        if len(node_stack) < 10:
            labels_str = ", ".join(map(str, node_stack))
        else:
            labels_str = f"{len(node_stack)} labels"
        with tqdm(
                desc=f"finding canonical taints for {labels_str}",
                leave=False,
                delay=5.0,
                bar_format="{l_bar}{bar}| [{elapsed}<{remaining}, {rate_fmt}{postfix}]'",
                total=sum(node.label for node in node_stack),
        ) as t:
            while node_stack:
                node = node_stack.pop()
                t.update(node.label)
                if node.parent_one is None:
                    assert node.parent_two is None
                    taints.add(self.file_offset(node))
                else:
                    parent1, parent2 = node.parent_one, node.parent_two
                    # a node will always have either zero or two parents.
                    # labels that are reused will reuse their associated nodes.
                    # all other nodes are unions.
                    assert parent1 is not None and parent2 is not None
                    if parent1 not in history:
                        history.add(parent1)
                        node_stack.append(parent1)
                        t.total += parent1.label
                    if parent2 not in history:
                        history.add(parent2)
                        node_stack.append(parent2)
                        t.total += parent2.label
        return Taints(taints)


    def function_trace(self) -> Iterator[FunctionEntry]:
        """Iterates over all of the :class:`FunctionEntry` events in this trace.

        This is equivalent to::

            iter(event for event in self if isinstance(event, FunctionEntry))

        However, concrete implementations such as :class:`polytracker.database.DBProgramTrace` might have more efficient
        implementations.

        """
        return iter(event for event in self if isinstance(event, FunctionEntry))

    def num_function_calls(self) -> int:
        """Returns the number of function calls in this trace."""
        return sum(1 for _ in self.function_trace())

    def num_function_calls_that_touched_taint(self) -> int:
        return sum(1 for func in self.function_trace() if func.touched_taint)

    def num_basic_block_entries(self) -> int:
        """Returns the number of basic block entries in this trace."""
        return sum(1 for event in self if isinstance(event, BasicBlockEntry))

    def next_function_entry(self, after: Optional[FunctionEntry] = None) -> Optional[FunctionEntry]:
        """Returns the next function entry, or None if none exists"""
        if after is None:
            try:
                return next(iter(self.function_trace()))
            except StopIteration:
                return None
        function_return = after.function_return
        if function_return is None:
            next_event = after.next_control_flow_event
        else:
            next_event = function_return.returning_to
        while next_event is not None:
            if isinstance(next_event, FunctionEntry):
                return next_event
        return None

    @property
    def entrypoint(self) -> Optional[FunctionInvocation]:
        """Returns the entrypoint to this trace (*i.e.*, its first :class:`FunctionInvocation`, typically ``main``)."""
        try:
            return FunctionInvocation(next(iter(self.function_trace())))
        except StopIteration:
            return None

    @abstractmethod
    def __getitem__(self, uid: int) -> TraceEvent:
        """Returns the trace event associated with the given identifier.

        Raises:
            KeyError: if the event does not exist.

        Equivalent to::

            self.get_event(uid)

        """
        raise NotImplementedError()

    @abstractmethod
    def __contains__(self, uid: int):
        """Returns whether an event with the given ID exists in this trace.

        Equivalent to::

            self.has_event(uid)

        """
        raise NotImplementedError()

    @property
    def cfg(self) -> DiGraph[BasicBlock]:
        """The static control flow graph associated with this trace."""
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
        """Calculates whether the trace's control flow graph is connected."""
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


def common_parent_directory(*paths: Union[Path, str]) -> Path:
    """Returns the deepest parent directory common to every path in paths"""
    p = []
    for path in paths:
        if not isinstance(path, Path):
            path = Path(path)
        p.append(path.absolute())
    return Path(commonpath(p))


class RunTraceCommand(Subcommand[TraceCommand]):
    name = "run"
    help = "run an instrumented binary"
    parent_type = TraceCommand

    def __init_arguments__(self, parser):
        parser.add_argument("--no-bb-trace", action="store_true", help="do not trace at the basic block level")
        parser.add_argument(
            "--output-db",
            "-o",
            type=str,
            default="polytracker.db",
            help="path to the output database (default is polytracker.db)",
        )
        parser.add_argument("INSTRUMENTED_BINARY", type=str, help="the instrumented binary to run")
        parser.add_argument("INPUT_FILE", type=str, help="the file to track")
        parser.add_argument("args", nargs=REMAINDER)

    @staticmethod
    @PolyTrackerREPL.register("run_trace")
    def run_trace(
            instrumented_binary_path: Union[str, Path],
            input_file_path: Union[str, Path],
            no_bb_trace: bool = False,
            output_db_path: Optional[Union[str, Path]] = None,
            args=(),
            return_trace: bool = True,
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

        Returns:
            The program trace or the instrumented binary's exit code

        """
        can_run_natively = PolyTrackerREPL.registered_globals["CAN_RUN_NATIVELY"]

        if output_db_path is None:
            # use a temporary file
            tmpdir: Optional[TemporaryDirectory] = TemporaryDirectory()
            output_db_path = Path(tmpdir.name) / "polytracker.db"  # type: ignore
        else:
            if not isinstance(output_db_path, Path):
                output_db_path = Path(output_db_path)
            tmpdir = None

        if not isinstance(instrumented_binary_path, Path):
            instrumented_binary_path = Path(instrumented_binary_path)

        if not isinstance(input_file_path, Path):
            input_file_path = Path(input_file_path)

        if output_db_path.exists():
            PolyTrackerREPL.warning(f'<style fg="gray">{output_db_path}</style> already exists')

        if can_run_natively:
            kwargs = {}
            instrumented_binary_path = str(instrumented_binary_path)
        else:
            cwd = common_parent_directory(input_file_path, output_db_path, instrumented_binary_path)
            kwargs = {"cwd": str(cwd)}

            input_file_path = input_file_path.absolute().relative_to(cwd)
            output_db_path = output_db_path.absolute().relative_to(cwd)
            instrumented_binary_path = str(instrumented_binary_path.absolute().relative_to(cwd))
            if not instrumented_binary_path.startswith("."):
                instrumented_binary_path = f"./{instrumented_binary_path}"

        cmd_args = [instrumented_binary_path] + list(args) + [str(input_file_path)]
        env = {"POLYPATH": str(input_file_path), "POLYTRACE": ["1", "0"][no_bb_trace], "POLYDB": str(output_db_path)}
        if can_run_natively:
            retval = subprocess.call(cmd_args, env=env)  # type: ignore
        else:
            run_command = PolyTrackerREPL.commands["docker_run"]
            retval = run_command(args=cmd_args, interactive=True, env=env, **kwargs)
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
            return_trace=False,
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
