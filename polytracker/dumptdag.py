from ctypes import Structure, c_int32, c_uint32, c_uint64, c_uint8, c_ulonglong, sizeof
from io import SEEK_SET
from pathlib import Path
from struct import Struct
from typing import BinaryIO, List, Iterable
import sys


#TODO (hbrodin): Completely unchecked values. Only parse files from trusted sources...


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

class SourceTaint(Taint):
  __

class labels:
  def __init__(self, hdr: FileHdr, f: BinaryIO):
    self.hdr = hdr
    self.f = f

  def count(self) -> int:
    return int(self.hdr.tdag_mapping_size/sizeof(c_uint64))

  def value(self, label : int) -> c_uint64:
    storedvalue = c_uint64()
    self.f.seek(self.hdr.tdag_mapping_offset + sizeof(c_uint64)*label, SEEK_SET)
    self.f.readinto(storedvalue)
    return storedvalue




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
        print(f"Label {lbl}: {lbls.value(lbl)}")

      for sle in iter_sinklog(hdr, file):
        print(f"fdidx {sle.fdidx}, offset {sle.offset} label {sle.label}")

    


dump_tdag(sys.argv[1])
