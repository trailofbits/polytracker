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
    cast,
)
from pathlib import Path
from mmap import mmap, PROT_READ
from ctypes import Structure, c_int64, c_uint64, c_int32, c_uint32, c_uint8, sizeof

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


class TDHeader(Structure):
    _fields_ = [
        ("fd_mapping_offset", c_uint64),
        ("fd_mapping_count", c_uint64),
        ("tdag_mapping_offset", c_uint64),
        ("tdag_mapping_size", c_uint64),
        ("sink_mapping_offset", c_uint64),
        ("sink_mapping_size", c_uint64),
    ]

    def __repr__(self) -> str:
        return (
            f"FileHdr:\n\tfdmapping_ofs: {self.fd_mapping_offset}\n\tfdmapping_count: {self.fd_mapping_count}\n\t"
            f"tdag_mapping_offset: {self.tdag_mapping_offset}\n\ttdag_mapping_size: {self.tdag_mapping_size}\n\t"
            f"sink_mapping_offset: {self.sink_mapping_offset}\n\tsink_mapping_size: {self.sink_mapping_size}\n\t"
        )


class TDFDHeader(Structure):
    _fields_ = [
        ("fd", c_int32),
        ("name_offset", c_uint32),
        ("name_len", c_uint32),
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
    _fields_ = [("fdidx", c_uint8), ("offset", c_int64), ("label", c_uint32)]

    def __repr__(self) -> str:
        return f"TDSink fdidx: {self.fdidx} offset: {self.offset} label: {self.label}"


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
        self.header = TDHeader.from_buffer_copy(self.buffer)  # type: ignore

        assert self.header.fd_mapping_offset > 0
        assert self.header.tdag_mapping_offset > 0
        assert self.header.tdag_mapping_size > 0
        assert self.header.sink_mapping_offset > 0

        self.raw_nodes: Dict[int, int] = {}
        self.sink_cache: Dict[int, TDSink] = {}

        self.fd_headers: List[Tuple[Path, TDFDHeader]] = list(self.read_fd_headers())

    def read_fd_headers(self) -> Iterator[Tuple[Path, TDFDHeader]]:

        offset = self.header.fd_mapping_offset
        for i in range(0, self.header.fd_mapping_count):
            header_offset = offset + sizeof(TDFDHeader) * i
            fdhdr = TDFDHeader.from_buffer_copy(self.buffer, header_offset)  # type: ignore
            sbegin = offset + fdhdr.name_offset
            path = Path(str(self.buffer[sbegin : sbegin + fdhdr.name_len], "utf-8"))
            yield (path, fdhdr)

    @property
    def label_count(self):
        return int(self.header.tdag_mapping_size / sizeof(c_uint64))

    def read_node(self, label: int) -> int:
        if label in self.raw_nodes:
            return self.raw_nodes[label]

        offset = self.header.tdag_mapping_offset + sizeof(c_uint64) * label

        assert self.header.tdag_mapping_offset + self.header.tdag_mapping_size > offset

        result = c_uint64.from_buffer_copy(self.buffer, offset).value  # type: ignore
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
        for label in range(0, self.label_count):
            yield self.decode_node(label)

    def read_sink(self, offset: int) -> TDSink:
        if offset in self.sink_cache:
            return self.sink_cache[offset]

        assert self.header.sink_mapping_offset <= offset
        assert self.header.sink_mapping_offset + self.header.sink_mapping_size > offset

        result = TDSink.from_buffer_copy(self.buffer, offset)  # type: ignore

        self.sink_cache[offset] = result

        return result

    @property
    def sinks(self) -> Iterator[TDSink]:

        offset = self.header.sink_mapping_offset
        end = offset + self.header.sink_mapping_size

        while offset < end:
            yield self.read_sink(offset)
            offset += sizeof(TDSink)


class TDTaintOutput(TaintOutput):
    def __init__(self, source: Input, output_offset: int, label: int):
        super().__init__(source, output_offset, label)

    def taints(self) -> Taints:
        return super().taints()


class TDProgramTrace(ProgramTrace):
    def __init__(self, file: BinaryIO) -> None:
        self.tdfile: TDFile = TDFile(file)
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
        tdnode: TDNode = self.tdfile.decode_node(node.label)
        assert isinstance(tdnode, TDSourceNode)
        return ByteOffset(node.source, tdnode.offset)

    @property
    def functions(self) -> Iterable[Function]:
        return super().functions

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
    @PolyTrackerREPL.register("load_trace_tdag")
    def load(tdpath: Union[str, Path]) -> "TDProgramTrace":
        """loads a trace from a .tdag file emitted by an instrumented binary"""
        return TDProgramTrace(open(tdpath, "rb"))

    @property
    def inputs(self) -> Iterator[Input]:
        for path, fdhdr in self.tdfile.fd_headers:
            begin = fdhdr.prealloc_label_begin
            end = fdhdr.prealloc_label_end
            if isinstance(self.tdfile.decode_node(begin), TDSourceNode):
                yield Input(fdhdr.fd, str(path), end - begin)

    @property
    def output_taints(self) -> Iterator[TDTaintOutput]:
        for sink in self.tdfile.sinks:
            path, fdhdr = self.tdfile.fd_headers[sink.fdidx]
            begin = fdhdr.prealloc_label_begin
            end = fdhdr.prealloc_label_end
            offset = sink.offset
            label = sink.label
            yield TDTaintOutput(
                Input(fdhdr.fd, path, end - begin),
                offset,
                label,
            )

    @property
    def taint_forest(self) -> TaintForest:
        return self.tforest

    def inputs_affecting_control_flow(self) -> Taints:
        result: Set[ByteOffset] = set()
        for _, fdhdr in self.tdfile.fd_headers:
            begin = fdhdr.prealloc_label_begin
            end = fdhdr.prealloc_label_end
            for label in range(begin, end):
                node = self.taint_forest.get_node(label)
                if not node.is_canonical():
                    break
                if node.affected_control_flow:
                    result.add(self.file_offset(node))

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
        return super().__getitem__(label)

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
            begin = fdhdr.prealloc_label_begin
            end = fdhdr.prealloc_label_end
            source = Input(fdhdr.fd, str(path), end - begin)
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

    def run(self, args):
        with open(args.POLYTRACKER_TF, "rb") as f:
            tdfile = TDFile(f)
            print(tdfile.header)
            print(f"Number of labels: {tdfile.label_count}")

            if args.print_fd_headers:
                for i, h in enumerate(tdfile.fd_headers):
                    path = h[0]
                    lbl_begin = h[1].prealloc_label_begin
                    lbl_end = h[1].prealloc_label_end
                    print(f"{i}: {path} {lbl_begin} {lbl_end}")

            if args.print_taint_sinks:
                for s in tdfile.sinks:
                    print(f"{s} -> {tdfile.decode_node(s.label)}")

            if args.print_taint_nodes:
                for lbl in range(1, tdfile.label_count):
                    print(f"Label {lbl}: {tdfile.decode_node(lbl)}")
