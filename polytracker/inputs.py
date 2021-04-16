from pathlib import Path
from typing import Optional


class Input:
    def __init__(
            self,
            uid: int,
            path: str,
            size: int,
            track_start: int = 0,
            track_end: Optional[int] = None,
            content: Optional[bytes] = None
    ):
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
        if self.stored_content is not None:
            return self.stored_content
        elif not Path(self.path).exists():
            raise ValueError(f"Input {self.uid} did not have its content stored to the database (the instrumented "
                             f"binary was likely run with POLYSAVEINPUT=0) and the associated path {self.path!r} "
                             "does not exist!")
        with open(self.path, "rb") as f:
            self.stored_content = f.read()
        return self.stored_content

    def __hash__(self):
        return self.uid

    def __eq__(self, other):
        return isinstance(other, Input) and self.uid == other.uid and self.path == other.path
