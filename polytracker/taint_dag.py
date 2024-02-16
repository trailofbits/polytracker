from typing import (
    BinaryIO,
    Union,
    Iterable,
    Iterator,
    Optional,
    Dict,
    Tuple,
    List,
    Set,
    Type,
    cast,
)

from argparse import BooleanOptionalAction
from enum import Enum
from pathlib import Path
from mmap import mmap, PROT_READ
from ctypes import (
    Structure,
    c_char,
    c_int64,
    c_uint64,
    c_int32,
    c_uint32,
    c_uint8,
    c_uint16,
    sizeof,
)

from .plugins import Command
from .repl import PolyTrackerREPL
from .polytracker import ProgramTrace
from .inputs import Input
from .taint_forest import TaintForest, TaintForestNode
from .tracing import (
    BasicBlock,
    ByteOffset,
    Function,
    TaintAccess,
    TraceEvent,
    TaintOutput,
    Taints,
)


class TDFileMeta(Structure):
    """TDAG File metadata.

    File header describing the overall layout of the TDAG file.
    Corresponds to OutputFile::FileMeta in outputfile.h
    """

    _fields_ = [
        ("tdag", c_char * 4),
        ("magic", c_uint16),
        ("section_count", c_uint16),
    ]

    def __repr__(self) -> str:
        return f"TDFileMeta:\n\ttdag: {self.tdag}\n\tmagic: {self.magic}\n\tsection count: {self.section_count}\n"


class TDSectionMeta(Structure):
    """TDAG Section metadata.

    Section header describing a particular section in the TDAG file.
    Corresponds to OutputFile::SectionMeta in outputfile.h
    """

    _fields_ = [
        ("tag", c_uint32),
        ("align", c_uint32),
        ("offset", c_uint64),
        ("size", c_uint64),
    ]

    def __repr__(self) -> str:
        return f"TDSectionMeta:\n\ttag: {self.tag}\n\talign: {self.align}\n\toffset: {self.offset}\n\tsize: {self.size}\n"


class TDSourceSection:
    """TDAG Taint Sources section.

    Interprets the Taint Sources section in a TDAG file.
    Corresponds to Sources in sources.h.
    """

    def __init__(self, mem, hdr):
        self.mem = mem[hdr.offset : hdr.offset + hdr.size]

    def enumerate(self):
        for offset in range(0, len(self.mem), sizeof(TDFDHeader)):
            yield TDFDHeader.from_buffer_copy(self.mem[offset:])


class TDStringSection:
    """TDAG String Table section

    Interprets the String Table section in a TDAG file.
    Corresponds to StringTableBase in string_table.h.
    """

    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset : hdr.offset + hdr.size]
        self.align = hdr.align

    def read_string(self, offset):
        n = c_uint16.from_buffer_copy(self.section[offset:]).value
        assert len(self.section) >= offset + sizeof(c_uint16) + n
        return str(
            self.section[offset + sizeof(c_uint16) : offset + sizeof(c_uint16) + n],
            "utf-8",
        )


class TDLabelSection:
    """TDAG Labels section interprets the stored taint nodes section in a TDAG file. Corresponds to Labels in labels.h.

    We need to be careful about our memory usage here since some inputs /
    instrumented code can cause this section to become very large (GiB) and
    analysis to therefore become difficult.
    """

    def __init__(self, mem, hdr):
        self.label_section_start = hdr.offset
        self.label_section_end = hdr.offset + hdr.size - 1
        self.mem_reference = mem

    def read_raw(self, label) -> int:
        offset: int = self.label_section_start + (label * sizeof(c_int64))
        return c_uint64.from_buffer_copy(self.mem_reference, offset).value

    def count(self) -> int:
        return ((self.label_section_end + 1) - self.label_section_start) // sizeof(
            c_uint64
        )


class TDEnterFunctionEvent:
    """Emitted whenever execution enters a function.
    The callstack member is the callstack right before entering the function,
    having the function just entered as the last member of the callstack.
    """

    def __init__(self, callstack):
        """Callstack after entering function"""
        self.callstack = callstack

    def __repr__(self) -> str:
        return f"Enter: {self.callstack}"

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, TDEnterFunctionEvent):
            return self.callstack == __o.callstack
        return False


class TDLeaveFunctionEvent:
    """Emitted whenever execution leaves a function.
    The callstack member is the callstack right before leaving the function,
    having the function about to leave as the last member of the callstack.
    """

    def __init__(self, callstack):
        """Callstack before leaving function"""
        self.callstack = callstack

    def __repr__(self) -> str:
        return f"Leave: {self.callstack}"

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, TDLeaveFunctionEvent):
            return self.callstack == __o.callstack
        return False


class TDTaintedControlFlowEvent:
    """Emitted whenever a control flow change is influenced by tainted data.
    The label that influenced the control flow is available in the `label` member.
    Current callstack (including the function the control flow happened in) is available
    in the `callstack` member."""

    def __init__(self, callstack, label):
        self.callstack = callstack
        self.label = label

    def __repr__(self) -> str:
        return f"TaintedControlFlow label {self.label} callstack {self.callstack}"

    def __eq__(self, __o: object) -> bool:
        if isinstance(__o, TDTaintedControlFlowEvent):
            return self.label == __o.label and self.callstack == __o.callstack
        return False


class TDControlFlowLogSection:
    """TDAG Control flow log section

    Interprets the control flow log section in a TDAG file.
    Enables enumeration/random access of items.
    """

    class Event(Enum):
        """NOTE: MUST correspond to the members in the `ControlFlowLog::EventType`` in `control_flog_log.h`."""

        ENTER_FUNCTION = 0
        LEAVE_FUNCTION = 1
        TAINTED_CONTROL_FLOW = 2

    def __init__(self, mem, hdr):
        # save references into the main TDAG mmap buffer `mem`, since with
        # very large traced inputs `mem` can get unwieldy and OOMs are possible
        self.cflog_section_start = hdr.offset
        self.cflog_section_end = hdr.offset + hdr.size - 1
        self.mem_reference = mem
        # Call function_id_mapping to set funcmapping before use of cflog.
        self.funcmapping = None

    class VarInt:
        """A dataclass for representing encoded items from the cflog section."""

        value: int
        index: int

        def __init__(self, value, index):
            self.value = value
            self.index = index

        def __repr__(self):
            return f"value: {self.value}, tdag ending index: {self.index}"

    def _decode_varint(self, starting_index) -> VarInt:
        """Decode a `uint32_t varint` as defined in `control_flow_log.h`. Increment the global cflog index and update the global value upon return. Most varints require only one iteration before `0x80` (varint end) is seen. Called by `__iter__`. NOTE !resets the iteration index!"""
        shift = 0
        decoded_value = 0
        for j in range(starting_index, self.cflog_section_end):
            curr = c_uint8.from_buffer_copy(self.mem_reference, j).value
            decoded_value |= (curr & 0x7F) << shift
            if curr & 0x80 == 0:
                return TDControlFlowLogSection.VarInt(decoded_value, j + 1)
            shift += 7
        raise Exception(
            "Unable to decode VarInt from TDAG control flow log section; this TDAG may not have been properly written?"
        )

    @staticmethod
    def _align_callstack(target_function_id, callstack):
        """Every LeaveFunctionEvent should have its own, correct view
        into the full callstack. As we return 'up' the stack to the original caller, execution leaves each callee; each callee should have its own view into how we traveled 'down' to it.
        """
        if len(callstack) > 0:
            while callstack and callstack[-1] != target_function_id:
                yield TDLeaveFunctionEvent(callstack[:])
                callstack.pop()

    def function_id_mapping(self, id_to_name_array):
        """This method stores an array used to translate from function id to symbolic names. Generate input to this method (we use a list of function symbols statically obtained at instrumentation time) using one of polytracker's instrumentation-side cflog options. This is required for __iter__."""
        self.funcmapping = id_to_name_array

    def __iter__(self):
        """The cflog encoding scheme is defined in control_flow_log.h. Each entry should consist of a taint label and a callstack by function id."""
        callstack = []
        event: TDControlFlowLogSection.Event = None
        mem_index = self.cflog_section_start
        for idx in range(self.cflog_section_start, self.cflog_section_end):
            # do not roll off the end of the section!
            if mem_index + 1 >= self.cflog_section_end:
                if len(callstack) > 0:
                    yield TDLeaveFunctionEvent(callstack[:])
                    callstack.pop()
                break
            elif event is None:
                event = TDControlFlowLogSection.Event(
                    c_uint8.from_buffer_copy(self.mem_reference, mem_index).value
                )
                mem_index += 1
            else:
                varint = self._decode_varint(mem_index)
                mem_index = varint.index
                # hack: sometimes function_id otherwise hasnt been set
                function_id = varint.value
                if self.funcmapping is not None and len(self.funcmapping) > 0:
                    function_id = self.funcmapping[varint.value]

                if event == TDControlFlowLogSection.Event.ENTER_FUNCTION:
                    event = None
                    callstack.append(function_id)
                    yield TDEnterFunctionEvent(callstack[:])
                elif event == TDControlFlowLogSection.Event.LEAVE_FUNCTION:
                    event = None
                    yield from TDControlFlowLogSection._align_callstack(
                        function_id, callstack
                    )
                else:
                    varint = self._decode_varint(mem_index)
                    mem_index = varint.index
                    event = None
                    yield TDTaintedControlFlowEvent(callstack[:], varint.value)

        # Return back to last function called (replaces exit() etc.)
        yield from TDControlFlowLogSection._align_callstack(-1, callstack)


class TDSinkSection:
    """TDAG Sinks section

    Interprets the sink entries section in a TDAG file.
    Corresponds to TaintSinkBase in sink.h.
    """

    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset : hdr.offset + hdr.size]

    def enumerate(self):
        for offset in range(0, len(self.section), sizeof(TDSink)):
            yield TDSink.from_buffer_copy(self.section[offset:])


class TDBitmapSection:
    """Represents a bitmap section encoded by BitmapSectionBase.

    The only configuration currently supported is to have the BucketType template
    parameter of BitmapSectionBase as uint64_t. It also requires the endianess to
    not change as the implementation does not handle endianess in any specific way.
    """

    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset : hdr.offset + hdr.size]
        assert len(self.section) % 8 == 0  # Multiple of uint64_t

    def enumerate_set_bits(self):
        """Enumerates all bits that are set

        The index of each bit that is set will be yielded.
        """
        index = 0
        for offset in range(0, len(self.section), sizeof(c_uint64)):
            bucket = c_uint64.from_buffer_copy(self.section, offset).value
            if bucket == 0:
                index += 64  # No bits set, just advance the bit index
            else:
                # At least one bit is set, iterate over all bits and yield set bits
                for i in range(0, 64):
                    if (bucket >> i) & 1:
                        yield index
                    index += 1


class TDSourceIndexSection(TDBitmapSection):
    """Represents the source index section.

    It is a bitmap of all labels that are source taints.
    """

    def __init__(self, mem, hdr):
        super().__init__(mem, hdr)


class TDFunctionsSection:
    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset : hdr.offset + hdr.size]

    def __iter__(self):
        for offset in range(0, len(self.section), sizeof(TDFnHeader)):
            yield TDFnHeader.from_buffer_copy(self.section, offset)


class TDEventsSection:
    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset : hdr.offset + hdr.size]

    def __iter__(self):
        for offset in range(0, len(self.section), sizeof(TDEvent)):
            yield TDEvent.from_buffer_copy(self.section, offset)


class TDFDHeader(Structure):
    """Python representation of the SourceEntry from taint_source.h"""

    _fields_ = [
        ("name_offset", c_uint32),
        ("fd", c_int32),
        ("size", c_uint64),
    ]

    def invalid_size(self):
        return self.size == 0xFFFFFFFFFFFFFFFF

    def invalid_fd(self):
        return self.fd == -1


class TDFnHeader(Structure):
    _fields_ = [("name_offset", c_uint32)]


class TDNode:
    def __init__(self, affects_control_flow: bool = False):
        self.affects_control_flow = affects_control_flow

    def __repr__(self) -> str:
        return f"affects control flow {self.affects_control_flow}"


class TDSourceNode(TDNode):
    def __init__(self, idx: int, offset: int, affects_control_flow: bool = False):
        super().__init__(affects_control_flow)
        self.idx = idx
        self.offset = offset

    def __repr__(self) -> str:
        return f"TDSourceNode: {super().__repr__()} idx {self.idx} offset {self.offset}"


class TDRangeNode(TDNode):
    def __init__(self, first: int, last: int, affects_control_flow: bool = False):
        super().__init__(affects_control_flow)
        # First label of the range
        self.first = first
        # Last label of the range
        self.last = last

    def __repr__(self) -> str:
        return f"TDRangeNode: {super().__repr__()} [{self.first}, {self.last}]"


class TDUnionNode(TDNode):
    def __init__(self, left: int, right: int, affects_control_flow: bool = False):
        super().__init__(affects_control_flow)
        self.left = left
        self.right = right

    def __repr__(self) -> str:
        return f"TDUnionNode: {super().__repr__()} ({self.left}, {self.right})"


class TDUntaintedNode(TDNode):
    def __init__(self):
        super().__init__(False)

    def __repr__(self) -> str:
        return f"TDUntaintedNode: {super().__repr__()}"


class TDSink(Structure):
    """Python representation of the SinkLogEntry from sink.h"""

    # _pack_ = 1
    _fields_ = [("offset", c_int64), ("label", c_uint32), ("fdidx", c_uint8)]

    def __repr__(self) -> str:
        return f"TDSink fdidx: {self.fdidx} offset: {self.offset} label: {self.label}"


class TDEvent(Structure):
    _fields_ = [("kind", c_uint8), ("fnidx", c_uint16)]

    class Kind(Enum):
        ENTRY = 0
        EXIT = 1

    def __repr__(self) -> str:
        return f"kind: {self.Kind(self.kind).name} fnidx: {self.fnidx}"


TDSection = Union[
    TDLabelSection,
    TDSourceSection,
    TDStringSection,
    TDSinkSection,
    TDSourceIndexSection,
    TDFunctionsSection,
    TDEventsSection,
    TDControlFlowLogSection,
]


class TDFile:
    def __init__(self, file: BinaryIO) -> None:
        """Loads a TDAG file from disk into memory."""
        # This needs to be kept in sync with implementation in encoding.cpp
        self.source_taint_bit_shift = 63
        self.affects_control_flow_bit_shift = 62
        self.label_bits = 31
        self.label_mask = 0x7FFFFFFF
        self.val1_shift = self.label_bits
        self.source_index_mask = 0xFF
        self.source_index_bits = 8
        self.source_offset_mask = (1 << 54) - 1

        # We need to be careful with memory usage for sections expected to be large so they can be analysed without a lot of thrashing of the underlying filesystem and/or OOM.
        self.buffer = mmap(file.fileno(), 0, prot=PROT_READ)

        self.filemeta = TDFileMeta.from_buffer_copy(self.buffer)
        section_offset = sizeof(TDFileMeta)
        self.sections: List[TDSection] = []
        self.sections_by_type: Dict[Type[TDSection], TDSection] = {}
        for _ in range(0, self.filemeta.section_count):
            hdr = TDSectionMeta.from_buffer_copy(self.buffer, section_offset)
            if hdr.tag == 1:
                self.sections.append(TDSourceSection(self.buffer, hdr))
                self.sections_by_type[TDSourceSection] = self.sections[-1]
            elif hdr.tag == 2:
                self.sections.append(TDLabelSection(self.buffer, hdr))
                self.sections_by_type[TDLabelSection] = self.sections[-1]
            elif hdr.tag == 3:
                self.sections.append(TDStringSection(self.buffer, hdr))
                self.sections_by_type[TDStringSection] = self.sections[-1]
            elif hdr.tag == 4:
                self.sections.append(TDSinkSection(self.buffer, hdr))
                self.sections_by_type[TDSinkSection] = self.sections[-1]
            elif hdr.tag == 5:
                self.sections.append(TDSourceIndexSection(self.buffer, hdr))
                self.sections_by_type[TDSourceIndexSection] = self.sections[-1]
            elif hdr.tag == 6:
                self.sections.append(TDFunctionsSection(self.buffer, hdr))
                self.sections_by_type[TDFunctionsSection] = self.sections[-1]
            elif hdr.tag == 7:
                self.sections.append(TDEventsSection(self.buffer, hdr))
                self.sections_by_type[TDEventsSection] = self.sections[-1]
            elif hdr.tag == 8:
                self.sections.append(TDControlFlowLogSection(self.buffer, hdr))
                self.sections_by_type[TDControlFlowLogSection] = self.sections[-1]
            else:
                raise NotImplementedError("Unsupported section tag")
            # Need to update the section offset even if we didn't read
            # a particular section off of disk.
            section_offset += sizeof(TDSectionMeta)

        self.raw_nodes: Dict[int, int] = {}
        self.sink_cache: Dict[int, TDSink] = {}

        self.fd_headers: List[Tuple[Path, TDFDHeader]] = list(self.read_fd_headers())
        self.fn_headers: List[Tuple[str, TDFnHeader]] = list(self.read_fn_headers())

    def _get_section(self, wanted_type: Type[TDSection]) -> TDSection:
        return self.sections_by_type[wanted_type]

    def read_fd_headers(self) -> Iterator[Tuple[Path, TDFDHeader]]:
        sources = self.sections_by_type[TDSourceSection]
        strings = self.sections_by_type[TDStringSection]
        assert isinstance(sources, TDSourceSection)
        assert isinstance(strings, TDStringSection)

        yield from (
            (Path(strings.read_string(x.name_offset)), x) for x in sources.enumerate()
        )

    def read_fn_headers(self) -> Iterator[Tuple[str, TDFnHeader]]:
        functions = self.sections_by_type[TDFunctionsSection]
        strings = self.sections_by_type[TDStringSection]
        assert isinstance(functions, TDFunctionsSection)
        assert isinstance(strings, TDStringSection)

        for header in functions:
            name = strings.read_string(header.name_offset)
            yield name, header

    def input_labels(self) -> Iterator[int]:
        """Enumerates all taint sources (input byte offsets). Analogous to the size of the input in bytes that the instrumented program parsed."""
        source_index_section = self.sections_by_type[TDSourceIndexSection]
        assert isinstance(source_index_section, TDSourceIndexSection)
        return source_index_section.enumerate_set_bits()

    @property
    def label_count(self) -> int:
        """Enumerates all taint labels. Requires the label section to have been loaded and should throw a KeyError for the TDLabelSection if it is not available."""
        label_section = self.sections_by_type[TDLabelSection]
        assert isinstance(label_section, TDLabelSection)
        return label_section.count()

    def read_node(self, label: int) -> int:
        """Read a node by label. Requires the label section to have been loaded and should throw a KeyError for the TDLabelSection if it is not available."""
        if label in self.raw_nodes:
            return self.raw_nodes[label]
        label_section = self.sections_by_type[TDLabelSection]
        assert isinstance(label_section, TDLabelSection)
        result = label_section.read_raw(label)

        self.raw_nodes[label] = result
        return result

    def decode_node(self, label: int) -> TDNode:
        """Fetch a node from either the raw nodes array or the TDLabelSection. Requires the label section to have been loaded and should throw a KeyError for the TDLabelSection (from read_node()) if it is not available."""
        # Label zero represents untainted data
        if label == 0:
            return TDUntaintedNode()

        v = self.read_node(label)
        # This needs to be kept in sync with implementation in encoding.cpp
        st = (v >> self.source_taint_bit_shift) & 1
        affects_cf = (v >> self.affects_control_flow_bit_shift) & 1 != 0
        if st:
            idx = v & self.source_index_mask
            offset = (v >> self.source_index_bits) & self.source_offset_mask
            return TDSourceNode(idx, offset, affects_cf)
        else:
            v1 = (v >> self.val1_shift) & self.label_mask
            v2 = v & self.label_mask

            if v1 > v2:
                return TDUnionNode(v1, v2, affects_cf)
            else:
                return TDRangeNode(v1, v2, affects_cf)

    @property
    def nodes(self) -> Iterator[TDNode]:
        """Show all nodes in the trace file. Requires the label section to have been loaded and MAY throw a KeyError for the TDLabelSection if it is not available."""
        for label in range(1, self.label_count):
            yield self.decode_node(label)

    @property
    def sinks(self) -> Iterator[TDSink]:
        sink_section = self.sections_by_type[TDSinkSection]
        assert isinstance(sink_section, TDSinkSection)
        yield from sink_section.enumerate()

    def read_event(self, offset: int) -> TDEvent:
        return TDEvent.from_buffer_copy(self.buffer, offset)

    @property
    def events(self) -> Iterator[TDEvent]:
        events_section = self.sections_by_type[TDEventsSection]
        assert isinstance(events_section, TDEventsSection)
        yield from events_section


class TDTaintOutput(TaintOutput):
    def __init__(self, source: Input, output_offset: int, label: int):
        super().__init__(source, output_offset, label)

    def taints(self) -> Taints:
        raise NotImplementedError()


class TDProgramTrace(ProgramTrace):
    def __init__(self, file: BinaryIO, taint_forest=True) -> None:
        self.tdfile: TDFile = TDFile(file)
        if taint_forest:
            self.tforest: TDTaintForest = TDTaintForest(self)
        self._inputs = None

    def __contains__(self, uid: int):
        return super().__contains__(uid)

    def __getitem__(self, uid: int) -> TraceEvent:
        raise NotImplementedError()

    def __iter__(self) -> Iterator[TraceEvent]:
        raise NotImplementedError()

    def __len__(self) -> int:
        raise NotImplementedError()

    def access_sequence(self) -> Iterator[TaintAccess]:
        raise NotImplementedError()

    @property
    def basic_blocks(self) -> Iterable[BasicBlock]:
        raise NotImplementedError()

    def file_offset(self, node: TaintForestNode) -> ByteOffset:
        assert node.source is not None
        tdnode: TDNode = self.tdfile.decode_node(node.label)
        assert isinstance(tdnode, TDSourceNode)
        return ByteOffset(node.source, tdnode.offset)

    @property
    def functions(self) -> Iterable[Function]:
        raise NotImplementedError()

    def get_event(self, uid: int) -> TraceEvent:
        raise NotImplementedError()

    def get_function(self, name: str) -> Function:
        raise NotImplementedError()

    def has_event(self, uid: int) -> bool:
        raise NotImplementedError()

    def has_function(self, name: str) -> bool:
        raise NotImplementedError()

    @property
    def num_accesses(self) -> int:
        raise NotImplementedError()

    @property
    def outputs(self) -> Optional[Iterable[Input]]:
        return super().outputs

    @staticmethod
    @PolyTrackerREPL.register("load_trace_tdag")
    def load(tdpath: Union[str, Path], taint_forest=True) -> "TDProgramTrace":
        """loads a trace from a .tdag file emitted by an instrumented binary"""
        return TDProgramTrace(open(tdpath, "rb"), taint_forest)

    @property
    def inputs(self) -> Iterator[Input]:
        # TODO (hbrodin): Current implementation needs to do a lot of work
        # to determine if a file header is an input or not. Consider
        # implementation alternatives.
        seen: Set[int] = set()
        for source_label in self.tdfile.input_labels():
            source_node = self.tdfile.decode_node(source_label)
            assert isinstance(source_node, TDSourceNode)
            if source_node.idx not in seen:
                path, fd_header = self.tdfile.fd_headers[source_node.idx]
                yield Input(fd_header.fd, str(path), fd_header.size)
                seen.add(source_node.idx)

    @property
    def output_taints(self) -> Iterator[TDTaintOutput]:
        for sink in self.tdfile.sinks:
            path, fdhdr = self.tdfile.fd_headers[sink.fdidx]
            offset = sink.offset
            label = sink.label
            yield TDTaintOutput(
                Input(fdhdr.fd, str(path), fdhdr.size),
                offset,
                label,
            )

    @property
    def taint_forest(self) -> TaintForest:
        return self.tforest

    def inputs_affecting_control_flow(self) -> Taints:
        result: Set[ByteOffset] = set()

        for source_label in self.tdfile.input_labels():
            source_node = self.tdfile.decode_node(source_label)
            if source_node.affects_control_flow:
                tf_node = self.taint_forest.get_node(source_label)
                result.add(self.file_offset(tf_node))

        return Taints(result)


class TDTaintForestNode(TaintForestNode):
    def __init__(
        self,
        forest: "TDTaintForest",
        label: int,
        source: Optional[Input],
        affected_control_flow: bool = False,
        parent_labels: Optional[Tuple[int, int]] = None,
    ):
        super().__init__(label, source, affected_control_flow)
        self.forest: TDTaintForest = forest
        self.parents: Optional[Tuple[int, int]] = parent_labels

    def __repr__(self):
        return (
            f"label: {self.label} ; "
            f"input: {None if self.source is None else self.source.uid} ; "
            f"affected_control_flow: {self.affected_control_flow} ; "
            f"parent_one: {self.parents[0] if self.parents else None} ; "
            f"parent_two: {self.parents[1] if self.parents else None}"
        )

    @property
    def parent_labels(self) -> Optional[Tuple[int, int]]:
        return self.parents

    @property
    def parent_one(self) -> Optional["TDTaintForestNode"]:
        if self.parents is None:
            return None

        return self.forest.get_node(self.parents[0])

    @property
    def parent_two(self) -> Optional["TDTaintForestNode"]:
        if self.parents is None:
            return None

        return self.forest.get_node(self.parents[1])


class TDTaintForest(TaintForest):
    def __init__(self, trace: TDProgramTrace) -> None:
        self.trace: TDProgramTrace = trace
        self.node_cache: Dict[int, Optional[TDTaintForestNode]] = {}

        self.node_cache[0] = TDTaintForestNode(self, 0, None)
        for i in range(1, self.trace.tdfile.label_count):
            self.node_cache[i] = None

        self.synth_label_cnt: int = -1

    def __getitem__(self, label: int) -> Iterator[TaintForestNode]:
        raise NotImplementedError()

    def __len__(self) -> int:
        return len(self.node_cache)

    def get_synth_node_label(self) -> int:
        result = self.synth_label_cnt
        self.synth_label_cnt -= 1
        return result

    def create_node(self, label: int) -> TDTaintForestNode:
        node = self.trace.tdfile.decode_node(label)

        if isinstance(node, TDSourceNode):
            path, fdhdr = self.trace.tdfile.fd_headers[node.idx]
            source = Input(fdhdr.fd, str(path), fdhdr.size)
            return TDTaintForestNode(self, label, source, node.affects_control_flow)

        elif isinstance(node, TDUnionNode):
            return TDTaintForestNode(
                self, label, None, node.affects_control_flow, (node.left, node.right)
            )

        # TDRangeNode has to be unfolded into a tree of union nodes in a sum-like
        # fashion. The created intermediate nodes are given labels via
        # `get_synth_node_label()`. `curr` holds the current node to be unioned.
        # Initially it holds the first element of the range, but as the sum goes
        # on it holds the current intermediate node. The final union is given the
        # label of the original node and is returned.
        elif isinstance(node, TDRangeNode):
            curr: int = node.first
            for n in range(node.first + 1, node.last):
                synth_label = self.get_synth_node_label()
                self.node_cache[synth_label] = TDTaintForestNode(
                    self,
                    synth_label,
                    None,
                    node.affects_control_flow,
                    (curr, n),
                )
                curr = synth_label

            return TDTaintForestNode(
                self,
                label,
                None,
                node.affects_control_flow,
                (curr, node.last),
            )

        assert False

    def get_node(self, label: int, source: Optional[Input] = None) -> TDTaintForestNode:
        assert source is None

        if self.node_cache[label] is not None:
            return cast(TDTaintForestNode, self.node_cache[label])

        result = self.create_node(label)

        self.node_cache[label] = result

        return result

    def nodes(self) -> Iterator[TDTaintForestNode]:
        label = max(self.node_cache.keys())
        while label in self.node_cache:
            yield self.get_node(label)
            label -= 1


class TDInfo(Command):
    name = "info"
    help = "print trace file information"

    def __init_arguments__(self, parser):
        parser.add_argument("POLYTRACKER_TF", type=str, help="the trace file")
        parser.add_argument(
            "--print-fd-headers",
            "-f",
            action="store_true",
            help="print file descriptor headers",
        )
        parser.add_argument(
            "--print-fn-headers",
            "-x",
            action="store_true",
            help="print function headers",
        )
        parser.add_argument(
            "--print-taint-sinks",
            "-s",
            action="store_true",
            help="print taint sinks",
        )
        parser.add_argument(
            "--print-taint-nodes",
            "-n",
            action="store_true",
            help="print taint nodes (warning: not compatible with --cflog)",
        )

        parser.add_argument(
            "--print-function-trace",
            "-t",
            action="store_true",
            help="print function trace events",
        )

        parser.add_argument(
            "--cflog",
            "-c",
            action="store_true",
            help="Show info about control flow log trace events.",
        )

    def run(self, args):
        with open(args.POLYTRACKER_TF, "rb") as f:
            tdfile = TDFile(f)
            if args.labels:
                print(f"Number of labels: {tdfile.label_count}")

            if args.print_fd_headers:
                for i, h in enumerate(tdfile.fd_headers):
                    path = h[0]
                    print(f"{i}: {path}")

            if args.print_fn_headers:
                for i, h in enumerate(tdfile.fn_headers):
                    name = h[0]
                    print(f"{i}: {name}")

            if args.print_taint_sinks:
                for s in tdfile.sinks:
                    print(f"{s} -> {tdfile.decode_node(s.label)}")

            if args.print_taint_nodes and not args.labels:
                print(
                    "Cannot read the full taint label count since did not load the taint label trace. Please try again without setting --labels to False."
                )
            elif args.print_taint_nodes:
                for lbl in range(1, tdfile.label_count):
                    print(f"Label {lbl}: {tdfile.decode_node(lbl)}")

            if args.print_function_trace:
                for e in tdfile.events:
                    print(f"{e}")

            if args.cflog:
                cflog = tdfile._get_section(TDControlFlowLogSection)
                assert isinstance(cflog, TDControlFlowLogSection)
                for obj in cflog:
                    print(f"{obj}")
