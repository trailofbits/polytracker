from .repl import PolyTrackerREPL
from .polytracker import ProgramTrace

from typing import Union
from pathlib import Path
from mmap import mmap, PROT_READ
from ctypes import Structure, c_ulonglong


class TDFileHeader(Structure):
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


class TDFile:
    def __init__(self, mm: bytearray) -> None:
        self.memory_map = mm
        self.header = TDFileHeader.from_buffer_copy(self.memory_map)


class TDProgramTrace(ProgramTrace):
    def __init__(self, tdfile: TDFile) -> None:
        self.tdfile: TDFile = tdfile

    @staticmethod
    @PolyTrackerREPL.register("load_trace")
    def load(td_path: Union[str, Path]) -> "TDProgramTrace":
        """loads a trace from a .tdag file emitted by an instrumented binary"""
        with open(td_path, "rb") as f, mmap(f.fileno(), 0, prot=PROT_READ) as mm:
            yield TDProgramTrace(mm)
