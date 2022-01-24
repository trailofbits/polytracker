from contextlib import contextmanager
from ctypes import Structure, c_int32, c_uint32, c_uint64, c_uint8, c_ulonglong, sizeof
from io import SEEK_SET
from mmap import mmap, PROT_READ
from pathlib import Path
from typing import Iterable, List, Tuple, Union
import sys


# TODO (hbrodin): Completely unchecked values. Only parse files from trusted sources...

# This needs to be kept in sync with implementation in encoding.cpp
source_taint_bit_shift = 63
affects_control_flow_bit_shift = 62
label_bits = 31
label_mask = 0x7fffffff
val1_shift = label_bits
source_index_mask = 0xff
source_index_bits = 8
source_offset_mask = ((1 << 54)-1)


class FileHdr(Structure):
    _fields_ = [("fd_mapping_offset", c_ulonglong),
                ("fd_mapping_size", c_ulonglong),
                ("tdag_mapping_offset", c_ulonglong),
                ("tdag_mapping_size", c_ulonglong),
                ("sink_mapping_offset", c_ulonglong),
                ("sink_mapping_size", c_ulonglong)]

    def __repr__(self) -> str:
        return (
            f"FileHdr:\n\tfdmapping_ofs: {self.fd_mapping_offset}\n\tfdmapping_size: {self.fd_mapping_size}\n\t"
            f"tdag_mapping_offset: {self.tdag_mapping_offset}\n\ttdag_mapping_size: {self.tdag_mapping_size}\n\t"
            f"sink_mapping_offset: {self.sink_mapping_offset}\n\tsink_mapping_size: {self.sink_mapping_size}\n\t"
        )


class FDMappingHdr(Structure):
    _fields_ = [("fd", c_int32),
                ("namelen", c_uint32),
                ("prealloc_begin", c_uint32),
                ("prealloc_end", c_uint32)]


class SinkLogEntry(Structure):
    _pack_ = 1
    _fields_ = [("fdidx", c_uint8),
                ("offset", c_uint64),
                ("label", c_uint32)]

    def __repr__(self) -> str:
        return f"SinkLog fdidx: {self.fdidx} offset: {self.offset} label: {self.label}"


class Taint:
    def __init__(self, affects_control_flow: bool = False):
        self.affects_control_flow = affects_control_flow

    def __repr__(self) -> str:
        return f"affects control flow {self.affects_control_flow}"


class SourceTaint(Taint):
    def __init__(self, idx: int, offset: int, affects_control_flow: bool = False):
        super().__init__(affects_control_flow)
        self.idx = idx
        self.offset = offset

    def __repr__(self) -> str:
        return f"SourceTaint: {super().__repr__()} idx {self.idx} offset {self.offset}"


class RangeTaint(Taint):
    def __init__(self, first: int, last: int, affects_control_flow: bool = False):
        super().__init__(affects_control_flow)
        self.first = first
        self.last = last

    def __repr__(self) -> str:
        return f"RangeTaint: {super().__repr__()} [{self.first}, {self.last}]"


class UnionTaint(Taint):
    def __init__(self, left: int, right: int, affects_control_flow: bool = False):
        super().__init__(affects_control_flow)
        self.left = left
        self.right = right

    def __repr__(self) -> str:
        return f"UnionTaint: {super().__repr__()} ({self.left}, {self.right})"


@contextmanager
def open_output_file(file: Path):
    with open(file, "rb") as f, \
            mmap(f.fileno(), 0, prot=PROT_READ) as mm:
        yield OutputFile(mm)


class OutputFile:
    def __init__(self, mm: bytearray) -> None:
        self.hdr = FileHdr.from_buffer_copy(mm)
        self.mm = mm

    def fd_mappings(self) -> Iterable[Tuple[str, int, int]]:
        offset = self.hdr.fd_mapping_offset
        end = offset + self.hdr.fd_mapping_size

        while offset < end:
            fdmhdr = FDMappingHdr.from_buffer_copy(self.mm, offset)
            offset += sizeof(FDMappingHdr)

            s = str(self.mm[offset:offset+fdmhdr.namelen],
                    'utf-8')  # TODO (hbrodin): Encoding???
            offset += fdmhdr.namelen
            yield (s, fdmhdr.prealloc_begin, fdmhdr.prealloc_end)

    def sink_log(self) -> Iterable[SinkLogEntry]:
        offset = self.hdr.sink_mapping_offset
        end = offset + self.hdr.sink_mapping_size

        while offset < end:
            sle = SinkLogEntry.from_buffer_copy(self.mm, offset)
            yield sle
            offset += sizeof(SinkLogEntry)

    def sink_log_labels(self) -> List[int]:
        offset = self.hdr.sink_mapping_offset + \
            sizeof(c_uint64) + sizeof(c_uint8)
        step = sizeof(SinkLogEntry)
        end = offset + self.hdr.sink_mapping_size
        labels = []

        last = 0
        while offset < end:
            v = c_uint32.from_buffer_copy(self.mm, offset).value
            if v != last:
                labels.append(v)
                last = v

            offset += step
        return labels

    def label_count(self) -> int:
        return int(self.hdr.tdag_mapping_size/sizeof(c_uint64))

    def raw_taint(self, label: int) -> int:
        offset = self.hdr.tdag_mapping_offset + sizeof(c_uint64)*label
        return c_uint64.from_buffer_copy(self.mm, offset).value

    def decoded_taint(self, label: int) -> Union[SourceTaint, RangeTaint, UnionTaint]:
        v = self.raw_taint(label)
        # This needs to be kept in sync with implementation in encoding.cpp
        st = (v >> source_taint_bit_shift) & 1
        affects_cf = (v >> affects_control_flow_bit_shift) & 1
        if st:
            idx = v & source_index_mask
            offset = (v >> source_index_bits) & source_offset_mask
            return SourceTaint(idx, offset, affects_cf)
        else:
            v1 = (v >> val1_shift) & label_mask
            v2 = v & label_mask

            if v1 > v2:
                return UnionTaint(v1, v2, affects_cf)
            else:
                return RangeTaint(v1, v2, affects_cf)


def dump_tdag(file: Path):
    with open_output_file(file) as f:
        print(f.hdr)
        print(f"Number of labels: {f.label_count()}")

        for i, e in enumerate(f.fd_mappings()):
            print(f"{i}: {e[0]} {e[1]}")

        for lbl in range(1, f.label_count()):
            print(f"Label {lbl}: {f.decoded_taint(lbl)}")

        for e in f.sink_log():
            print(f"{e} -> {f.decoded_taint(e.label)}")

# NOTE (hbrodin): Assemes source taint was preallocated
def gen_source_taint_used(tdagpath: Path, sourcefile: Path) -> bytearray:

    def iter_source_labels_not_affecting_cf(f: OutputFile, lbl: int):

        seen = set()
        labels = [lbl]
        while len(labels) > 0:
            l = labels[0]
            labels = labels[1:]

            if l in seen:
                continue

            t = f.decoded_taint(l)

            # It is already marked in the source labels if it affects control flow
            if t.affects_control_flow:
                continue

            if isinstance(t, SourceTaint):
                yield (l, t)

            elif isinstance(t, UnionTaint):
                labels.append(t.left)
                labels.append(t.right)
            elif isinstance(t, RangeTaint):
                for l in range(t.first, t.last+1):
                    labels.append(l)

    with open_output_file(tdagpath) as f:
        srcidx, src_begin, src_end = next(
            x for x in f.fd_mappings() if x[0] == sourcefile)
        filelen = src_end - src_begin
        marker = bytearray(filelen)

        # Initially, mark all source taint that affects control flow
        for idx, lbl in enumerate(range(src_begin, src_end)):
            if f.decoded_taint(lbl).affects_control_flow:
                marker[idx] = 1

        # Now, iterate all source labels in the taint sink. As an optimization, if
        # the taint affects_control_flow, move one. It already spilled into the source
        # taint and was marked above
        l = f.sink_log_labels()
        for lbl in l:
            for (srclabel, t) in iter_source_labels_not_affecting_cf(f, lbl):
                marker[srclabel - src_begin] = 1
        return marker


def marker_to_ranges(m: bytearray) -> List[Tuple[int, int]]:
    ranges = []
    start = None
    for i, v in enumerate(m):
        if v == 0:
            if start is None:
                start = i
        if v == 1:
            if start is not None:
                ranges.append((start, i))
                start = None
    if start is not None:
        ranges.append((start, len(m)))
    return ranges


def cavity_detection(tdag: OutputFile, sourcefile: Path):
    m = gen_source_taint_used(tdag, sourcefile)
    for r in marker_to_ranges(m):
        print(r)


if __name__ == "__main__":
  # dump_tdag(sys.argv[1])
  cavity_detection(sys.argv[1], sys.argv[2])
