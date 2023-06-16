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
    """TDAG Labels section

    Interprets the stored taint nodes section in a TDAG file.
    Corresponds to Labels in labels.h.
    """

    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset : hdr.offset + hdr.size]

    def read_raw(self, label):
        return c_uint64.from_buffer_copy(self.section, label * sizeof(c_uint64)).value

    def count(self):
        return len(self.section) // sizeof(c_uint64)


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
    Enables enumeration/random access of items
    """

    # NOTE: MUST correspond to the members in the `ControlFlowLog::EventType`` in `control_flog_log.h`.
    ENTER_FUNCTION = 0
    LEAVE_FUNCTION = 1
    TAINTED_CONTROL_FLOW = 2

    @staticmethod
    def _decode_varint(buffer):
        shift = 0
        val = 0
        while buffer:
            curr = c_uint8.from_buffer_copy(buffer, 0).value
            val |= (curr & 0x7F) << shift
            shift += 7
            buffer = buffer[1:]
            if curr & 0x80 == 0:
                break

        return val, buffer

    @staticmethod
    def _align_callstack(target_function_id, callstack):
        while callstack and callstack[-1] != target_function_id:
            yield TDLeaveFunctionEvent(callstack[:])
            callstack.pop()

    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset : hdr.offset + hdr.size]
        self.funcmapping = None

    def __iter__(self):
        buffer = self.section
        callstack = []
        while buffer:
            event = c_uint8.from_buffer_copy(buffer, 0).value
            buffer = buffer[1:]
            function_id, buffer = TDControlFlowLogSection._decode_varint(buffer)
            if self.funcmapping != None:
                function_id = self.funcmapping[function_id]

            if event == TDControlFlowLogSection.ENTER_FUNCTION:
                callstack.append(function_id)
                yield TDEnterFunctionEvent(callstack[:])
            elif event == TDControlFlowLogSection.LEAVE_FUNCTION:
                # Align call stack, if needed
                yield from TDControlFlowLogSection._align_callstack(
                    function_id, callstack
                )

                # TODO(hbrodin): If the callstack doesn't contain function_id at all, this will break.
                yield TDLeaveFunctionEvent(callstack[:])
                callstack.pop()
            else:
                # Align call stack, if needed
                yield from TDControlFlowLogSection._align_callstack(
                    function_id, callstack
                )

                label, buffer = TDControlFlowLogSection._decode_varint(buffer)
                yield TDTaintedControlFlowEvent(callstack[:], label)

        # Drain callstack with artifical TDLeaveFunction events (using a dummy function id that doesn't exist)
        yield from TDControlFlowLogSection._align_callstack(-1, callstack)

    def function_id_mapping(self, id_to_name_array):
        """This method stores an array used to translate from function id to symbolic names"""
        self.funcmapping = id_to_name_array


class TDSinkSection:
    """TDAG Sinks section

    Interprets the sink entries section in a TDAG file.
    Corresponds to TaintSinkBase in sink.h.
    """

    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset : hdr.offset + hdr.size]

    def __len__(self):
        return len(self.section) // sizeof(TDSink)

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

    def __hash__(self):
        return hash((self.name_offset, self.fd, self.size))

    def invalid_size(self):
        return self.size == 0xFFFFFFFFFFFFFFFF

    def invalid_fd(self):
        return self.fd == -1


class TDFnHeader(Structure):
    _fields_ = [("name_offset", c_uint32)]


class TDNode:
    def __init__(self, affects_control_flow: bool = False):
        self.affects_control_flow = affects_control_flow

    def __hash__(self):
        return hash(self.affects_control_flow)

    def __eq__(self, other):
        return (
            isinstance(other, TDNode)
            and other.affects_control_flow == self.affects_control_flow
        )

    def __str__(self) -> str:
        return f"affects control flow {self.affects_control_flow}"

    def __repr__(self):
        return f"{self.__class__.__name__}(affects_control_flow={self.affects_control_flow})"


class TDSourceNode(TDNode):
    def __init__(self, idx: int, offset: int, affects_control_flow: bool = False):
        super().__init__(affects_control_flow)
        self.idx = idx
        self.offset = offset

    def __hash__(self):
        return hash((super().__hash__(), self.idx, self.offset))

    def __eq__(self, other):
        return (
            isinstance(other, TDSourceNode)
            and super().__eq__(other)
            and self.idx == other.idx
            and self.offset == other.offset
        )

    def __str__(self) -> str:
        return f"TDSourceNode: {super()!s} idx {self.idx} offset {self.offset}"

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(idx={self.idx}, offset={self.offset}, "
            f"affects_control_flow={self.affects_control_flow})"
        )


class TDRangeNode(TDNode):
    def __init__(self, first: int, last: int, affects_control_flow: bool = False):
        super().__init__(affects_control_flow)
        # First label of the range
        self.first = first
        # Last label of the range
        self.last = last

    def __hash__(self):
        return hash((super().__hash__(), self.first, self.last))

    def __eq__(self, other):
        return (
            isinstance(other, TDRangeNode)
            and super().__eq__(other)
            and self.first == other.first
            and self.last == other.last
        )

    def __str__(self) -> str:
        return f"TDRangeNode: {super()!s} [{self.first}, {self.last}]"

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(first={self.first}, last={self.last}, "
            f"affects_control_flow={self.affects_control_flow})"
        )


class TDUnionNode(TDNode):
    def __init__(self, left: int, right: int, affects_control_flow: bool = False):
        super().__init__(affects_control_flow)
        self.left = left
        self.right = right

    def __hash__(self):
        return hash((super().__hash__(), self.left, self.right))

    def __eq__(self, other):
        return (
            isinstance(other, TDUnionNode)
            and super().__eq__(other)
            and self.left == other.left
            and self.right == other.right
        )

    def __str__(self) -> str:
        return f"TDUnionNode: {super()!s} ({self.left}, {self.right})"

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(left={self.left}, right={self.right}, "
            f"affects_control_flow={self.affects_control_flow})"
        )


class TDUntaintedNode(TDNode):
    def __init__(self):
        super().__init__(False)

    def __hash__(self):
        return hash(self.__class__.__name__)

    def __eq__(self, other):
        return isinstance(other, TDUntaintedNode)

    def __str__(self) -> str:
        return f"TDUntaintedNode: {super()!s}"

    def __repr__(self):
        return f"{self.__class__.__name__}()"


class TDSink(Structure):
    """Python representation of the SinkLogEntry from sink.h"""

    # _pack_ = 1
    _fields_ = [("offset", c_int64), ("label", c_uint32), ("fdidx", c_uint8)]

    def __str__(self) -> str:
        return f"TDSink fdidx: {self.fdidx} offset: {self.offset} label: {self.label}"


class TDEvent(Structure):
    _fields_ = [("kind", c_uint8), ("fnidx", c_uint16)]

    class Kind(Enum):
        ENTRY = 0
        EXIT = 1

    def __str__(self) -> str:
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


class TDNodeIterator:
    def __init__(self, file: "TDFile", reverse: bool = False):
        self.file: TDFile = file
        self.reverse: bool = reverse

    def __iter__(self) -> Iterator[TDNode]:
        if self.reverse:
            r = range(self.file.label_count - 1, 0, -1)
        else:
            r = range(1, self.file.label_count)
        for label in r:
            yield self.file.decode_node(label)

    def __len__(self):
        return self.file.label_count - 1

    def __getitem__(self, index: int) -> TDNode:
        if self.reverse:
            return self.file.decode_node(self.file.label_count - index - 1)
        else:
            return self.file.decode_node(index + 1)

    def __reversed__(self) -> "TDNodeIterator":
        return self.__class__(file=self.file, reverse=not self.reverse)


class TDNodeAffectingControlFlowIterator:
    def __init__(self, file: "TDFile"):
        self.file: TDFile = file
        self._len: int = -1

    def __iter__(self) -> Iterator[Tuple[int, TDNode]]:
        for label, node in enumerate(TDNodeIterator(self.file), start=1):
            if node.affects_control_flow:
                yield label, node

    def __len__(self):
        if self._len < 0:
            self._len = sum(1 for _ in self)
        return self._len


class TDFile:
    def __init__(self, file: BinaryIO) -> None:
        # This needs to be kept in sync with implementation in encoding.cpp
        self.source_taint_bit_shift = 63
        self.affects_control_flow_bit_shift = 62
        self.label_bits = 31
        self.label_mask = 0x7FFFFFFF
        self.val1_shift = self.label_bits
        self.source_index_mask = 0xFF
        self.source_index_bits = 8
        self.source_offset_mask = (1 << 54) - 1

        self.buffer = mmap(file.fileno(), 0, prot=PROT_READ)

        self.filemeta = TDFileMeta.from_buffer_copy(self.buffer)
        section_offset = sizeof(TDFileMeta)
        self.sections: List[TDSection] = []
        self.sections_by_type: Dict[Type[TDSection], TDSection] = {}
        for i in range(0, self.filemeta.section_count):
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

            section_offset += sizeof(TDSectionMeta)

        self.raw_nodes: Dict[int, int] = {}
        self.sink_cache: Dict[int, TDSink] = {}

        self.fd_headers: List[Tuple[Path, TDFDHeader]] = list(self.read_fd_headers())
        self.fn_headers: List[Tuple[str, TDFnHeader]] = list(self.read_fn_headers())

    def _get_section(self, wanted_type: Type[TDSection]) -> TDSection:
        return self.sections_by_type[wanted_type]

    def read_fd_headers(self) -> Iterator[Tuple[Path, TDFDHeader]]:
        sources = cast(TDSourceSection, self.sections_by_type[TDSourceSection])
        strings = cast(TDStringSection, self.sections_by_type[TDStringSection])

        yield from (
            (Path(strings.read_string(x.name_offset)), x) for x in sources.enumerate()
        )

    def read_fn_headers(self) -> Iterator[Tuple[str, TDFnHeader]]:
        functions = cast(TDFunctionsSection, self.sections_by_type[TDFunctionsSection])
        strings = cast(TDStringSection, self.sections_by_type[TDStringSection])

        for header in functions:
            name = strings.read_string(header.name_offset)
            yield name, header

    def input_labels(self) -> Iterator[int]:
        """Enumerates all taint labels that are input labels (source taint)"""
        source_indices = cast(
            TDSourceIndexSection, self.sections_by_type[TDSourceIndexSection]
        )
        return source_indices.enumerate_set_bits()

    @property
    def label_count(self):
        return self.sections_by_type[TDLabelSection].count()

    def read_node(self, label: int) -> int:
        if label in self.raw_nodes:
            return self.raw_nodes[label]
        labels = cast(TDLabelSection, self.sections_by_type[TDLabelSection])
        result = labels.read_raw(label)
        self.raw_nodes[label] = result
        return result

    def decode_node(self, label: int) -> TDNode:
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
    def nodes(self) -> TDNodeIterator:
        return TDNodeIterator(self)

    @property
    def nodes_affecting_control_flow(self) -> TDNodeAffectingControlFlowIterator:
        return TDNodeAffectingControlFlowIterator(self)

    @property
    def num_sinks(self) -> int:
        sinks = cast(TDSinkSection, self.sections_by_type[TDSinkSection])
        return len(sinks)

    @property
    def sinks(self) -> Iterator[TDSink]:
        sinks = cast(TDSinkSection, self.sections_by_type[TDSinkSection])
        yield from sinks.enumerate()

    def read_event(self, offset: int) -> TDEvent:
        return TDEvent.from_buffer_copy(self.buffer, offset)

    @property
    def events(self) -> Iterator[TDEvent]:
        yield from cast(TDEventsSection, self.sections_by_type[TDEventsSection])


class TDTaintOutput(TaintOutput):
    def __init__(self, source: Input, output_offset: int, label: int):
        super().__init__(source, output_offset, label)

    def taints(self) -> Taints:
        raise NotImplementedError()


class TDProgramTrace(ProgramTrace):
    def __init__(self, file: BinaryIO) -> None:
        self.tdfile: TDFile = TDFile(file)
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
    def load(tdpath: Union[str, Path]) -> "TDProgramTrace":
        """loads a trace from a .tdag file emitted by an instrumented binary"""
        return TDProgramTrace(open(tdpath, "rb"))

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

    def __str__(self):
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
            help="print taint nodes",
        )

        parser.add_argument(
            "--print-function-trace",
            "-t",
            action="store_true",
            help="print function trace events",
        )

        parser.add_argument(
            "--print-control-flow-log",
            "-c",
            action="store_true",
            help="print function trace events",
        )

    def run(self, args):
        with open(args.POLYTRACKER_TF, "rb") as f:
            tdfile = TDFile(f)
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

            if args.print_taint_nodes:
                for lbl in range(1, tdfile.label_count):
                    print(f"Label {lbl}: {tdfile.decode_node(lbl)}")

            if args.print_function_trace:
                for e in tdfile.events:
                    print(f"{e}")

            if args.print_control_flow_log:
                cflog = tdfile._get_section(TDControlFlowLogSection)
                assert isinstance(cflog, TDControlFlowLogSection)
                for obj in cflog:
                    print(f"{obj}")
