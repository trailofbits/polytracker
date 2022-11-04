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

from enum import Enum
from pathlib import Path
from mmap import mmap, PROT_READ
from ctypes import Structure, c_char, c_int64, c_uint64, c_int32, c_uint32, c_uint8, c_uint16, sizeof

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
    _fields_ = [
        ("tdag", c_char*4),
        ("magic", c_uint16),
        ("section_count", c_uint16),
    ]

    def __repr__(self) -> str:
        return f"TDFileMeta:\n\ttdag: {self.tdag}\n\tmagic: {self.magic}\n\tsection count: {self.section_count}\n"
        

class TDSectionMeta(Structure):
    _fields_ = [
        ("tag", c_uint32),
        ("align", c_uint32),
        ("offset", c_uint64),
        ("size", c_uint64),
    ]

    def __repr__(self) -> str:
        return f"TDSectionMeta:\n\ttag: {self.tag}\n\talign: {self.align}\n\toffset: {self.offset}\n\tsize: {self.size}\n" 


class TDSourceSection:
    def __init__(self, mem, hdr):
        self.mem = mem[hdr.offset:hdr.offset+hdr.size]

    def enumerate(self):
        for offset in range(0,len(self.mem), sizeof(TDFDHeader)):
            yield TDFDHeader.from_buffer_copy(self.mem[offset:])


    
class TDStringSection:
    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset:hdr.offset+hdr.size]
        self.align = hdr.align
    
    def read_string(self, offset):
        n = c_uint16.from_buffer_copy(self.section[offset:]).value
        assert len(self.section) > offset + n
        return str(self.section[offset + sizeof(c_uint16) : offset + sizeof(c_uint16) + n], "utf-8")
    
class TDLabelSection:
    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset:hdr.offset+hdr.size]

    def read_raw(self, label):
        return c_uint64.from_buffer_copy(self.section[label * sizeof(c_uint64):]).value

    def count(self):
        return len(self.section) // sizeof(c_uint64)

class TDSinkSection:
    def __init__(self, mem, hdr):
        self.section = mem[hdr.offset:hdr.offset+hdr.size]

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
        assert len(self.section) % 8 == 0 # Multiple of uint64_t

    def enumerate_set_bits(self):
        """Enumerates all bits that are set

        The index of each bit that is set will be yielded.
        """
        index = 0
        for offset in range(0, len(self.section), sizeof(c_uint64)):
            bucket = c_uint64.from_buffer_copy(self.section[offset:]).value
            if bucket == 0:
                index += 64 # No bits set, just advance the bit index
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






class TDHeader(Structure):
    _fields_ = [
        ("fd_mapping_offset", c_uint64),
        ("fd_mapping_count", c_uint64),
        ("tdag_mapping_offset", c_uint64),
        ("tdag_mapping_size", c_uint64),
        ("sink_mapping_offset", c_uint64),
        ("sink_mapping_size", c_uint64),
        ("fn_mapping_offset", c_uint64),
        ("fn_mapping_count", c_uint64),
        ("fn_trace_offset", c_uint64),
        ("fn_trace_count", c_uint64),
    ]

    def __repr__(self) -> str:
        return (
            f"FileHdr:\n\tfdmapping_ofs: {self.fd_mapping_offset}\n\tfdmapping_count: {self.fd_mapping_count}\n\t"
            f"tdag_mapping_offset: {self.tdag_mapping_offset}\n\ttdag_mapping_size: {self.tdag_mapping_size}\n\t"
            f"sink_mapping_offset: {self.sink_mapping_offset}\n\tsink_mapping_size: {self.sink_mapping_size}\n\t"
            f"fnmapping_offset: {self.fn_mapping_offset}\n\tfnmapping_count: {self.fn_mapping_count}\n\t"
            f"fntrace_offset: {self.fn_trace_offset}\n\tfntrace_count: {self.fn_trace_count}\n\t"
        )


class TDFDHeader(Structure):
    _fields_ = [
        ("name_offset", c_uint32),
        ("fd", c_int32),
    ]


class TDFnHeader(Structure):
    _fields_ = [
        ("name_offset", c_uint32),
        ("name_len", c_uint32),
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
        self.sections = []
        for i in range(0, self.filemeta.section_count):
            hdr = TDSectionMeta.from_buffer_copy(self.buffer, section_offset)
            if hdr.tag == 1:
                self.sections.append(TDSourceSection(self.buffer, hdr))
            elif hdr.tag == 2:
                self.sections.append(TDLabelSection(self.buffer, hdr))
            elif hdr.tag == 3:
                self.sections.append(TDStringSection(self.buffer, hdr))
            elif hdr.tag == 4:
                self.sections.append(TDSinkSection(self.buffer, hdr))
            elif hdr.tag == 5:
                self.sections.append(TDSourceIndexSection(self.buffer, hdr))
            else:
                raise Exception("Unsupported section tag")
                
            section_offset += sizeof(TDSectionMeta)

        self.raw_nodes: Dict[int, int] = {}
        self.sink_cache: Dict[int, TDSink] = {}

        self.fd_headers: List[Tuple[Path, TDFDHeader]] = list(self.read_fd_headers())
        self.fn_headers: List[Tuple[str, TDFnHeader]] = list(self.read_fn_headers())

    def _read_mapping_header(
        self, offset: int, count: int, header_type
    ) -> Iterator[Tuple[str, Structure]]:
        for i in range(0, count):
            header_offset = offset + sizeof(header_type) * i
            hdr = header_type.from_buffer_copy(self.buffer, header_offset)  # type: ignore
            sbegin = offset + hdr.name_offset
            name = str(self.buffer[sbegin : sbegin + hdr.name_len], "utf-8")
            yield name, hdr

    def _get_section(self, wanted_type):
        return next(filter(lambda x: isinstance(x, wanted_type), self.sections))

    def read_fd_headers(self) -> Iterator[Tuple[Path, TDFDHeader]]:
        sources = self._get_section(TDSourceSection)
        strings = self._get_section(TDStringSection)

        yield from map(lambda x: (Path(strings.read_string(x.name_offset)), x), sources.enumerate())

    def input_labels(self) -> Iterator[int]:
        return self._get_section(TDSourceIndexSection).enumerate_set_bits()

    @property
    def label_count(self):
        return self._get_section(TDLabelSection).count()

    def read_node(self, label: int) -> int:
        if label in self.raw_nodes:
            return self.raw_nodes[label]

        result = self._get_section(TDLabelSection).read_raw(label)

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

    @property
    def sinks(self) -> Iterator[TDSink]:
        yield from self._get_section(TDSinkSection).enumerate()

    def read_event(self, offset: int) -> TDEvent:
        return TDEvent.from_buffer_copy(self.buffer, offset)

    @property
    def events(self) -> Iterator[TDEvent]:

        offset = self.header.fn_trace_offset
        end = offset + self.header.fn_trace_count * sizeof(TDEvent)

        while offset < end:
            yield self.read_event(offset)
            offset += sizeof(TDEvent)


class TDTaintOutput(TaintOutput):
    def __init__(self, source: Input, output_offset: int, label: int):
        super().__init__(source, output_offset, label)

    def taints(self) -> Taints:
        return super().taints()


class TDProgramTrace(ProgramTrace):
    def __init__(self, file: BinaryIO) -> None:
        self.tdfile: TDFile = TDFile(file)
        self.tforest: TDTaintForest = TDTaintForest(self)
        self._inputs = None

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
        # TODO (hbrodin): Current implementation needs to do a lot of work
        # to determine if a file header is an input or not. Consider
        # consider implementation alternatives.
        seen: Set[int] = set()
        for source_label in self.tdfile.input_labels():
            source_node = self.tdfile.decode_node(source_label)
            if not source_node.idx in seen:
                path, fd_header = self.tdfile.fd_headers[source_node.idx]
                yield Input(fd_header.fd, str(path), 0)
                seen.add(source_node.idx)


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
            #begin = fdhdr.prealloc_label_begin
            #end = fdhdr.prealloc_label_end
            #source = Input(fdhdr.fd, str(path), end - begin)
            source = Input(fdhdr.fd, str(path), 0)
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

    def run(self, args):
        with open(args.POLYTRACKER_TF, "rb") as f:
            tdfile = TDFile(f)
            print(tdfile.header)
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
