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

from typing import Union, Iterable, Iterator, Optional, Dict, Tuple, List
from pathlib import Path
from mmap import mmap, PROT_READ
from ctypes import Structure, c_uint64, c_int32, c_uint32, c_uint8, sizeof


class TDHeader(Structure):
    _fields_ = [
        ("fd_mapping_offset", c_uint64),
        ("fd_mapping_size", c_uint64),
        ("tdag_mapping_offset", c_uint64),
        ("tdag_mapping_size", c_uint64),
        ("sink_mapping_offset", c_uint64),
        ("sink_mapping_size", c_uint64),
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
        return f"TDSink fdidx: {self.fdidx} offset: {self.offset} label: {self.label}"


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

        self.raw_nodes: Dict[int, int] = {}
        self.sink_cache: Dict[int, TDSink] = {}

        self.fd_headers: List[Tuple[str, TDFDHeader]] = list(self.read_fd_headers())

    def read_fd_headers(self) -> Iterator[Tuple[str, TDFDHeader]]:
        assert self.header.fd_mapping_offset > 0
        assert self.header.fd_mapping_size > 0

        offset = self.header.fd_mapping_offset
        end = offset + self.header.fd_mapping_size

        while offset < end:
            fdhdr = TDFDHeader.from_buffer_copy(self.buffer, offset)
            offset += sizeof(TDFDHeader)
            path = str(self.buffer[offset : offset + fdhdr.namelen], "utf-8")
            yield (path, fdhdr)
            offset += len(path)

    @property
    def label_count(self):
        return int(self.header.tdag_mapping_size / sizeof(c_uint64))

    def read_node(self, label: int) -> int:
        if label in self.raw_nodes:
            return self.raw_nodes[label]

        offset = self.header.tdag_mapping_offset + sizeof(c_uint64) * label

        assert self.header.tdag_mapping_offset + self.header.tdag_mapping_size > offset

        result = c_uint64.from_buffer_copy(self.buffer, offset).value
        self.raw_nodes[label] = result
        return result

    def decode_node(self, label: int) -> TDNode:
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
        assert self.header.tdag_mapping_offset > 0
        assert self.header.tdag_mapping_size > 0

        for label in range(0, self.label_count):
            yield self.decode_node(label)

    def read_sink(self, offset: int) -> TDSink:
        if offset in self.sink_cache:
            return self.sink_cache[offset]

        assert self.header.sink_mapping_offset <= offset
        assert self.header.sink_mapping_offset + self.header.sink_mapping_size > offset

        result = TDSink.from_buffer_copy(self.buffer, offset)

        self.sink_cache[offset] = result

        return result

    @property
    def sinks(self) -> Iterator[TDSink]:
        assert self.header.sink_mapping_offset > 0
        assert self.header.sink_mapping_size > 0

        offset = self.header.sink_mapping_offset
        end = offset + self.header.sink_mapping_size

        while offset < end:
            yield self.read_sink(offset)
            offset += sizeof(TDSink)


class TDProgramTrace(ProgramTrace):
    def __init__(self, tdfile: TDFile) -> None:
        self.tdfile: TDFile = TDFile(tdfile)
        self.tforest: TDTaintForest = TDTaintForest(self)

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
        assert node.source is not None
        offset = self.tdfile.decode_node(node.label).offset
        return ByteOffset(node.source, offset)

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
    def inputs(self) -> Iterator[Input]:
        for path, fdhdr in self.tdfile.fd_headers:
            begin = fdhdr.prealloc_label_begin
            end = fdhdr.prealloc_label_end
            if isinstance(self.tdfile.decode_node(begin), TDSourceNode):
                yield Input(fdhdr.fd, path, end - begin)

    @property
    def output_taints(self) -> Iterator[TaintOutput]:
        for sink in self.tdfile.sinks:
            path, fdhdr = self.tdfile.fd_headers[sink.fdidx]
            begin = fdhdr.prealloc_label_begin
            end = fdhdr.prealloc_label_end
            offset = sink.offset
            label = sink.label
            yield TaintOutput(
                Input(fdhdr.fd, path, end - begin),
                offset,
                label,
            )

    @property
    def taint_forest(self) -> TaintForest:
        return self.tforest


class TDTaintForestNode(TaintForestNode):
    def __init__(
        self,
        label: int,
        source: Input,
        affected_control_flow: bool = False,
        parent_one: "TDTaintForestNode" = None,
        parent_two: "TDTaintForestNode" = None,
    ):
        super().__init__(label, source, affected_control_flow)
        self.parents = (parent_one, parent_two)

    def __repr__(self):
        i = None if self.source is None else self.source.uid
        l = None if self.parent_one is None else self.parent_one.label
        r = None if self.parent_two is None else self.parent_two.label
        return (
            f"label: {self.label} ; "
            f"input: {i} ; "
            f"affected_control_flow: {self.affected_control_flow} ; "
            f"parent_one: {l} ; "
            f"parent_two: {r}"
        )

    @property
    def parent_one(self) -> Optional["TDTaintForestNode"]:
        return self.parents[0]

    @property
    def parent_two(self) -> Optional["TDTaintForestNode"]:
        return self.parents[1]


class TDTaintForest(TaintForest):
    def __init__(self, trace: TDProgramTrace) -> None:
        self.trace: TDProgramTrace = trace
        self.node_cache: Dict[int, Optional[TDTaintForestNode]] = {}

        self.node_cache[0] = TDTaintForestNode(0, None)
        for i in range(1, self.trace.tdfile.label_count):
            self.node_cache[i] = None

        self.synth_label_cnt: int = -1

    def __len__(self) -> int:
        return len(self.node_cache)

    def get_synth_node_label(self):
        result = self.synth_label_cnt
        self.synth_label_cnt -= 1
        return result

    def create_nodes(self, label: int) -> None:

        stack = [label]

        while len(stack) > 0:

            label = stack[-1]

            if self.node_cache[label] is not None:
                stack.pop()
                continue

            node = self.trace.tdfile.decode_node(label)

            if isinstance(node, TDSourceNode):
                path, fdhdr = self.trace.tdfile.fd_headers[node.idx]
                begin = fdhdr.prealloc_label_begin
                end = fdhdr.prealloc_label_end
                source = Input(fdhdr.fd, path, end - begin)
                self.node_cache[label] = TDTaintForestNode(
                    label, source, node.affects_control_flow
                )
                stack.pop()

            elif isinstance(node, TDUnionNode):
                l = self.node_cache[node.left]
                r = self.node_cache[node.right]

                if l is None:
                    stack.append(node.left)

                if r is None:
                    stack.append(node.right)

                if (r is not None) and (l is not None):
                    self.node_cache[label] = TDTaintForestNode(
                        label, None, node.affects_control_flow, l, r
                    )
                    stack.pop()

            elif isinstance(node, TDRangeNode):
                is_ready = True
                for n in range(node.first, node.last + 1):
                    if self.node_cache[n] is None:
                        stack.append(n)
                        is_ready = False

                if not is_ready:
                    continue

                sum = self.node_cache[node.first]
                for n in range(node.first + 1, node.last):
                    l = self.get_synth_node_label()
                    sum = TDTaintForestNode(
                        l,
                        None,
                        node.affects_control_flow,
                        sum,
                        self.node_cache[n],
                    )
                    self.node_cache[l] = sum

                self.node_cache[label] = TDTaintForestNode(
                    label,
                    None,
                    node.affects_control_flow,
                    sum,
                    self.node_cache[node.last],
                )

                stack.pop()

    def nodes(self) -> Iterator[TDTaintForestNode]:
        label = max(self.node_cache.keys())
        while label in self.node_cache:
            if self.node_cache[label] is None:
                self.create_nodes(label)

            assert self.node_cache[label] is not None

            yield self.node_cache[label]

            label -= 1
