"""A module for modeling taint sources like input files"""

from pathlib import Path
from typing import List, Optional, Tuple


class InputProperties:
    def __init__(
        self, unused_byte_offsets: List[int], out_of_order_byte_offsets: List[int], file_seeks: List[Tuple[int, int, int]]
    ):
        self.unused_byte_offsets: List[int] = unused_byte_offsets
        self.file_seeks: List[Tuple[int, int, int]] = file_seeks
        self.out_of_order_byte_offsets: List[int] = out_of_order_byte_offsets

    def __bool__(self):
        return not self.unused_byte_offsets and not self.out_of_order_byte_offsets and not self.file_seeks


class Input:
    """A source of taint"""

    def __init__(
        self,
        uid: int,
        path: str,
        size: int,
        track_start: int = 0,
        track_end: Optional[int] = None,
        content: Optional[bytes] = None,
    ):
        """Initializes a taint source.

        Args:
            uid: A unique ID for the input (unique per trace).
            path: The path to the input when the trace was run.
            size: The number of bytes read from the input.
            track_start: The byte offset of the source where tracing started.
            track_end: The byte offset of the source where tracing ended. (Defaults to the end of the input.)
            content: The original bytes of the input.
        """
        self.uid: int = uid
        self.path: str = path
        self.size: int = size
        self.track_start: int = track_start
        if track_end is None:
            self.track_end: int = size
        else:
            self.track_end = track_end
        self.stored_content: Optional[bytes] = content

    @property
    def content(self) -> bytes:
        """The original bytes of the input, if available.

        Raises:
            ValueError: If the input did not have its content stored to the database (*e.g.*, if the instrumented binary
                        was run with ``POLYSAVEINPUT=0``) and :attr:`self.path`
                        does not exist.

        """
        if self.stored_content is not None:
            return self.stored_content
        elif not Path(self.path).exists():
            raise ValueError(
                f"Input {self.uid} did not have its content stored to the database (the instrumented "
                f"binary was likely run with POLYSAVEINPUT=0) and the associated path {self.path!r} "
                "does not exist!"
            )
        with open(self.path, "rb") as f:
            self.stored_content = f.read()
        return self.stored_content

    def __hash__(self):
        return self.uid

    def __eq__(self, other):
        return isinstance(other, Input) and self.uid == other.uid and self.path == other.path
