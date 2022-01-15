from ctypes import Structure, c_int32, c_uint32, c_uint64, c_uint8, c_ulonglong, sizeof
from io import SEEK_SET
from pathlib import Path
from struct import Struct
from typing import BinaryIO, List, Iterable, Union
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

class FDMappingHdr(Structure):
  _fields_ = [("fd", c_int32),
              ("size", c_uint32)]


class SinkLogEntry(Structure):
  _pack_ = 1
  _fields_ = [("fdidx", c_uint8),
              ("offset", c_uint64),
              ("label", c_uint32)]

def read_fd_mappings(hdr: FileHdr, f : BinaryIO) -> List[str]:
  f.seek(hdr.fd_mapping_offset, SEEK_SET)
  fdm = f.read(hdr.fd_mapping_size)

  ret = []

  offset = 0
  while offset < len(fdm):
    fdmhdr = FDMappingHdr.from_buffer_copy(fdm[offset:offset+sizeof(FDMappingHdr)])
    offset += sizeof(FDMappingHdr)

    s = str(fdm[offset:offset+fdmhdr.size], 'utf-8') # TODO (hbrodin): Encoding???
    offset += fdmhdr.size

    ret.append(s)
  return ret

def iter_sinklog(hdr: FileHdr, path : Path) -> Iterable[SinkLogEntry]:
  with open(path, "rb") as f:
    f.seek(hdr.sink_mapping_offset)
    sle = SinkLogEntry()
    size = hdr.sink_mapping_size
    read = 0
    while read < size:
      nread = f.readinto(sle)
      if nread == 0:
        return
      read += nread
      yield sle


class Taint:
  def __init__(self, affects_control_flow :bool = False):
    self.affects_control_flow = False

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

class labels:
  def __init__(self, hdr: FileHdr, f: BinaryIO):
    self.hdr = hdr
    self.f = f

  def count(self) -> int:
    return int(self.hdr.tdag_mapping_size/sizeof(c_uint64))

  def value(self, label : int) -> int:
    storedvalue = c_uint64()
    self.f.seek(self.hdr.tdag_mapping_offset + sizeof(c_uint64)*label, SEEK_SET)
    self.f.readinto(storedvalue)
    return storedvalue.value

  def taint(self, label : int) -> Union[SourceTaint, RangeTaint, UnionTaint]:
    v = self.value(label)
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
  with open(file, "rb") as f:
      hdr = FileHdr()
      f.readinto(hdr)

      print(hdr.fd_mapping_offset)
      print(hdr.fd_mapping_size)
      print(hdr.tdag_mapping_offset)
      print(hdr.tdag_mapping_size)
      print(hdr.sink_mapping_offset)
      print(hdr.sink_mapping_size)

      fdm = read_fd_mappings(hdr, f)

      for idx, name in enumerate(fdm):
        print(f"Index: {idx} name: {name}")

      lbls = labels(hdr, f)
      print(f"Number of labels: {lbls.count()}")
      for lbl in range(1, lbls.count()):
        print(f"Label {lbl}: {lbls.value(lbl)}->{lbls.taint(lbl)}")

      for sle in iter_sinklog(hdr, file):
        print(f"fdidx {sle.fdidx}, offset {sle.offset} label {sle.label}")

    


dump_tdag(sys.argv[1])
