from abc import abstractmethod
from typing import Iterator, Optional

from .inputs import Input


class TaintForestNode:
    def __init__(self, label: int, source: Input):
        self.label: int = label
        self.source: Input = source

    @property
    @abstractmethod
    def parent_one(self) -> Optional["TaintForestNode"]:
        raise NotImplementedError()

    @property
    @abstractmethod
    def parent_two(self) -> Optional["TaintForestNode"]:
        raise NotImplementedError()

    def is_canonical(self) -> bool:
        return self.parent_one is None and self.parent_two is None

    def __eq__(self, other):
        return isinstance(other, TaintForestNode) and other.label == self.label and other.source == self.source

    def __hash__(self):
        return hash((self.label, self.source))


class TaintForest:
    @abstractmethod
    def nodes(self) -> Iterator[TaintForestNode]:
        raise NotImplementedError()

    def __iter__(self):
        return self.nodes()

    @abstractmethod
    def __len__(self):
        raise NotImplementedError()
