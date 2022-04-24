from typing import (
    Callable,
    Dict,
    FrozenSet,
    ItemsView,
    Iterable,
    Iterator,
    KeysView,
    List,
    Optional,
    Tuple,
)

import cxxfilt
import graphviz
import os

from .graphs import DiGraph


class FunctionInfo:
    def __init__(
        self,
        name: str,
        cmp_bytes: Dict[str, List[int]],
        input_bytes: Optional[Dict[str, List[int]]] = None,
        called_from: Iterable[str] = (),
    ):
        self.name: str = name
        self.called_from: FrozenSet[str] = frozenset(called_from)
        self._cmp_bytes: Dict[str, List[int]] = cmp_bytes
        if input_bytes is None:
            self._input_bytes: Dict[str, List[int]] = cmp_bytes
        else:
            self._input_bytes = input_bytes
        self._demangled_name: Optional[str] = None

    @property
    def demangled_name(self) -> str:
        if self._demangled_name is None:
            self._demangled_name = self.name
            if self._demangled_name.startswith("dfs$"):
                self._demangled_name = self._demangled_name[4:]
            self._demangled_name = cxxfilt.demangle(self._demangled_name)
        return self._demangled_name  # type: ignore

    def source_size(self, source: str) -> int:
        if source not in self.taint_sources:
            raise KeyError(source)
        elif os.path.exists(source):
            return os.stat(source).st_size
        else:
            # find the largest byte this trace touched
            return max(self.input_bytes[source])

    def taint_source_sizes(self) -> Dict[str, int]:
        return {source: self.source_size(source) for source in self.taint_sources}

    @property
    def input_bytes(self) -> Dict[str, List[int]]:
        return self._input_bytes

    @property
    def cmp_bytes(self) -> Dict[str, List[int]]:
        return self._cmp_bytes

    @property
    def taint_sources(self) -> KeysView[str]:
        return self.input_bytes.keys()

    @staticmethod
    def tainted_chunks(byte_offsets: Iterable[int]) -> Iterator[Tuple[int, int]]:
        start_offset: Optional[int] = None
        last_offset: Optional[int] = None
        for offset in sorted(byte_offsets):
            if last_offset is None:
                start_offset = offset
            elif offset != last_offset and offset != last_offset + 1:
                yield start_offset, last_offset + 1  # type: ignore
                start_offset = offset
            last_offset = offset
        if last_offset is not None:
            yield start_offset, last_offset + 1  # type: ignore

    def input_chunks(self) -> Iterator[Tuple[str, Tuple[int, int]]]:
        for source, byte_offsets in self.input_bytes.items():
            for start, end in FunctionInfo.tainted_chunks(byte_offsets):
                yield source, (start, end)

    def cmp_chunks(self) -> Iterator[Tuple[str, Tuple[int, int]]]:
        for source, byte_offsets in self.cmp_bytes.items():
            for start, end in FunctionInfo.tainted_chunks(byte_offsets):
                yield source, (start, end)

    def __getitem__(self, input_source_name: str) -> List[int]:
        return self.input_bytes[input_source_name]

    def __iter__(self) -> Iterable[str]:
        return self.taint_sources

    def items(self) -> ItemsView[str, List[int]]:
        return self.input_bytes.items()

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return isinstance(other, FunctionInfo) and other.name == self.name

    def __str__(self):
        return self.demangled_name

    def __repr__(self):
        return (
            f"{self.__class__.__name__}(name={self.name!r}, cmp_bytes={self.cmp_bytes!r}, "
            f"input_bytes={self.input_bytes!r}, called_from={self.called_from!r})"
        )


class CFG(DiGraph[FunctionInfo]):
    def __init__(self):
        super().__init__()

    def to_dot(
        self,
        comment: Optional[str] = "PolyTracker Program Trace",
        labeler: Optional[Callable[[FunctionInfo], str]] = None,
        node_filter=None,
    ) -> graphviz.Digraph:
        function_labels: Dict[str, str] = {}

        def func_labeler(f):
            if labeler is not None:
                return labeler(f)
            elif f.name in function_labels:
                return f"{f.name} ({function_labels[f.name]})"
            else:
                return f.name

        return super().to_dot(comment, labeler=func_labeler, node_filter=node_filter)
