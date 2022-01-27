from .repl import PolyTrackerREPL
from .polytracker import ProgramTrace
from .inputs import Input
from .taint_forest import TaintForest, TaintForestNode
from .tracing import (
    BasicBlock,
    ByteOffset,
    Function,
    Input,
    TaintAccess,
    TraceEvent,
    TaintOutput,
)

from typing import Union, Iterable, Iterator, Optional
from pathlib import Path
from mmap import mmap, PROT_READ
from ctypes import Structure, c_ulonglong, c_uint64, c_int32, c_uint32, c_uint8, sizeof


class TDHeader(Structure):
    _fields_ = [
        ("fd_mapping_offset", c_ulonglong),
        ("fd_mapping_size", c_ulonglong),
        ("tdag_mapping_offset", c_ulonglong),
        ("tdag_mapping_size", c_ulonglong),
        ("sink_mapping_offset", c_ulonglong),
        ("sink_mapping_size", c_ulonglong),
    ]

    def __repr__(self) -> str:
        return (
            f"FileHdr:\n\tfdmapping_ofs: {self.fd_mapping_offset}\n\tfdmapping_size: {self.fd_mapping_size}\n\t"
            f"tdag_mapping_offset: {self.tdag_mapping_offset}\n\ttdag_mapping_size: {self.tdag_mapping_size}\n\t"
            f"sink_mapping_offset: {self.sink_mapping_offset}\n\tsink_mapping_size: {self.sink_mapping_size}\n\t"
        )


class TDFDHeader(Structure):
    _fields_ = [
        ("fd", c_int32),
        ("namelen", c_uint32),
        # First label of the pre-allocated range
        ("prealloc_label_begin", c_uint32),
        # One-past last label of the pre-allocated range
        ("prealloc_label_end", c_uint32),
    ]


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


class TDSink(Structure):
    _pack_ = 1
    _fields_ = [("fdidx", c_uint8), ("offset", c_uint64), ("label", c_uint32)]

    def __repr__(self) -> str:
        return f"SinkLog fdidx: {self.fdidx} offset: {self.offset} label: {self.label}"


class TDFile:
    def __init__(self, buffer: bytearray) -> None:
        # This needs to be kept in sync with implementation in encoding.cpp
        self.source_taint_bit_shift = 63
        self.affects_control_flow_bit_shift = 62
        self.label_bits = 31
        self.label_mask = 0x7FFFFFFF
        self.val1_shift = self.label_bits
        self.source_index_mask = 0xFF
        self.source_index_bits = 8
        self.source_offset_mask = (1 << 54) - 1

        self.buffer = buffer
        self.header = TDHeader.from_buffer_copy(self.buffer)

    @property
    def label_count(self):
        return int(self.header.tdag_mapping_size / sizeof(c_uint64))

    def read_raw_node(self, label: int) -> int:
        offset = self.header.tdag_mapping_offset + sizeof(c_uint64) * label
        return c_uint64.from_buffer_copy(self.buffer, offset).value

    def decode_node(self, label: int) -> Union[TDSourceNode, TDRangeNode, TDUnionNode]:
        v = self.read_raw_node(label)
        # This needs to be kept in sync with implementation in encoding.cpp
        st = (v >> self.source_taint_bit_shift) & 1
        affects_cf = (v >> self.affects_control_flow_bit_shift) & 1
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


class TDProgramTrace(ProgramTrace):
    def __init__(self, tdfile: TDFile) -> None:
        self.tdfile: TDFile = TDFile(tdfile)

    def __contains__(self, uid: int):
        return super().__contains__(uid)

    def __getitem__(self, uid: int) -> TraceEvent:
        return super().__getitem__(uid)

    def __iter__(self) -> Iterator[TraceEvent]:
        return super().__iter__()

    def __len__(self) -> int:
        return super().__len__()

    def access_sequence(self) -> Iterator[TaintAccess]:
        return super().access_sequence()

    @property
    def basic_blocks(self) -> Iterable[BasicBlock]:
        return super().basic_blocks

    def file_offset(self, node: TaintForestNode) -> ByteOffset:
        return super().file_offset(node)

    @property
    def functions(self) -> Iterable[Function]:
        return super().functions

    def get_event(self, uid: int) -> TraceEvent:
        return super().get_event(uid)

    def get_event(self, uid: int) -> TraceEvent:
        return super().get_event(uid)

    def get_function(self, name: str) -> Function:
        return super().get_function(name)

    def has_event(self, uid: int) -> bool:
        return super().has_event(uid)

    def has_function(self, name: str) -> bool:
        return super().has_function(name)

    @property
    def num_accesses(self) -> int:
        return super().num_accesses

    @property
    def outputs(self) -> Optional[Iterable[Input]]:
        return super().outputs

    @staticmethod
    @PolyTrackerREPL.register("load_trace")
    def load(tdpath: Union[str, Path]) -> "TDProgramTrace":
        """loads a trace from a .tdag file emitted by an instrumented binary"""
        f = open(tdpath, "rb")
        return TDProgramTrace(mmap(f.fileno(), 0, prot=PROT_READ))

    @property
    def inputs(self) -> Iterable[Input]:
        # for label in range(1, self.tdfile.label_count):
        #     node = self.tdfile.decode_node(label)
        #     if isinstance(node, TDSourceNode):
        #         # Get the input file path by indexing via TDSourceNode.idx into fd_mapping_header
        #         yield Input(uid, path, size, start_offset)

        assert self.tdfile.header.fd_mapping_offset > 0
        assert self.tdfile.header.fd_mapping_size > 0

        offset = self.tdfile.header.fd_mapping_offset
        end = offset + self.tdfile.header.fd_mapping_size
        fdhdr = TDFDHeader.from_buffer_copy(self.tdfile.buffer, offset)

        while offset < end:
            node = self.tdfile.decode_node(fdhdr.prealloc_label_begin)

            if isinstance(node, TDSourceNode):
                # TODO (hbrodin): Encoding???
                path = str(self.tdfile.buffer[offset : offset + fdhdr.namelen], "utf-8")
                uid = hash(path + str(node.offset)) % (1 << 16)
                yield Input(uid, path, size=1, track_start=node.offset)

            offset += sizeof(TDFDHeader) + fdhdr.namelen
            fdhdr = TDFDHeader.from_buffer_copy(self.tdfile.buffer, offset)

    @property
    def output_taints(self) -> Iterable[TaintOutput]:
        assert self.tdfile.header.sink_mapping_offset > 0
        assert self.tdfile.header.sink_mapping_size > 0

        offset = self.tdfile.header.sink_mapping_offset
        end = self.tdfile.header.sink_mapping_size

        while offset < end:
            sink = TDSink.from_buffer_copy(self.tdfile.buffer, offset)
            source = next(x[1] for x in enumerate(self.inputs) if x[0] == sink.fdidx)
            yield TaintOutput(source, sink.offset, sink.label)
            offset += sizeof(TDSink)

    @property
    def taint_forest(self) -> TaintForest:
        return super().taint_forest
