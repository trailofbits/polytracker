from contextlib import contextmanager
from ctypes import Structure, c_int32, c_uint32, c_uint64, c_uint8, c_ulonglong, sizeof
from io import SEEK_SET
from mmap import mmap, PROT_READ
from pathlib import Path
from typing import Iterable, Tuple, Union
import sys


#TODO (hbrodin): Completely unchecked values. Only parse files from trusted sources...

# This needs to be kept in sync with implementation in encoding.cpp
source_taint_bit_shift = 63
affects_control_flow_bit_shift = 62
label_bits = 31
label_mask = 0x7fffffff
val1_shift = label_bits
source_index_mask = 0xff
source_index_bits = 8
source_offset_mask = ((1<<54)-1)

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
  def __init__(self, affects_control_flow :bool = False):
    self.affects_control_flow = affects_control_flow

  def __repr__(self) -> str:
      return f"affects control flow {self.affects_control_flow}"

class SourceTaint(Taint):
  def __init__(self, idx : int, offset: int, affects_control_flow : bool = False):
    super().__init__(affects_control_flow)
    self.idx = idx
    self.offset = offset

  def __repr__(self) -> str:
    return f"SourceTaint: {super().__repr__()} idx {self.idx} offset {self.offset}"

class RangeTaint(Taint): 
  def __init__(self, begin : int, end: int, affects_control_flow : bool = False):
    super().__init__(affects_control_flow)
    self.begin = begin
    self.end = end

  def __repr__(self) -> str:
    return f"RangeTaint: {super().__repr__()} [{self.begin}, {self.end}]"

class UnionTaint(Taint): 
  def __init__(self, left : int, right: int, affects_control_flow : bool = False):
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
  def __init__(self, mm : bytearray) -> None:
    self.hdr = FileHdr.from_buffer_copy(mm)
    self.mm = mm

  def fd_mappings(self) -> Iterable[Tuple[str, int, int]]:
    offset = self.hdr.fd_mapping_offset
    end = offset + self.hdr.fd_mapping_size

    while offset < end:
      fdmhdr = FDMappingHdr.from_buffer_copy(self.mm, offset)
      offset += sizeof(FDMappingHdr)

      s = str(self.mm[offset:offset+fdmhdr.namelen], 'utf-8') # TODO (hbrodin): Encoding???
      offset += fdmhdr.namelen
      yield (s, fdmhdr.prealloc_begin, fdmhdr.prealloc_end)


  def sink_log(self) -> Iterable[SinkLogEntry]:
    offset = self.hdr.sink_mapping_offset
    end = offset + self.hdr.sink_mapping_size
  
    while offset < end:
        sle = SinkLogEntry.from_buffer_copy(self.mm, offset)
        yield sle
        offset += sizeof(SinkLogEntry)

  def label_count(self) -> int:
    return int(self.hdr.tdag_mapping_size/sizeof(c_uint64))

  def raw_taint(self, label:int)->int:
    offset = self.hdr.tdag_mapping_offset + sizeof(c_uint64)*label
    return c_uint64.from_buffer_copy(self.mm, offset).value

  def decoded_taint(self, label : int) -> Union[SourceTaint, RangeTaint, UnionTaint]:
    v = self.raw_taint(label)
    # This needs to be kept in sync with implementation in encoding.cpp
    st = (v>>source_taint_bit_shift) & 1
    affects_cf = (v>>affects_control_flow_bit_shift) & 1
    if st:
      idx = v & source_index_mask
      offset = (v >> source_index_bits) & source_offset_mask
      return SourceTaint(idx, offset, affects_cf)
    else:
      v1 = (v>> val1_shift) & label_mask
      v2 = v & label_mask

      if v1 > v2:
        return UnionTaint(v1, v2, affects_cf)
      else:
        return RangeTaint(v1, v2, affects_cf)


def dump_tdag(file: Path):
  with open_output_file(file) as f:
    print(f.hdr)
    print(f"Number of labels: {f.label_count()}")

    for i, e in enumerate(f.fd_mappings()) :
      print(f"{i}: {e[0]} {e[1]}")

    for lbl in range(1, f.label_count()):
      print(f"Label {lbl}: {f.decoded_taint(lbl)}")

    for e in f.sink_log():
      print(f"{e} -> {f.decoded_taint(e.label)}")

dump_tdag(sys.argv[1])