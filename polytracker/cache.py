from collections import OrderedDict
from collections.abc import MutableSet as AbstractMutableSet
from typing import Callable, Generic, MutableSet as MutableSetType, Optional, TypeVar, Iterator

R = TypeVar("R")


class Memoized(Generic[R]):
    def __init__(self, func: Callable[..., R]):
        self.func = func
        self._set: bool = False
        self.cached: Optional[R] = None

    def __call__(self, *args, **kwargs) -> R:
        if not self._set:
            self._set = True
            self.cached = self.func(*args, **kwargs)
        return self.cached


def memoize(func: Callable[..., R]) -> Callable[..., R]:
    return Memoized(func)


class OrderedSet(Generic[R], AbstractMutableSet, MutableSetType[R]):
    def __init__(self, *items: R):
        self._items: OrderedDict[R, R] = OrderedDict()
        for i in items:
            self._items[i] = i

    def add(self, item: R):
        self._items[item] = item

    def discard(self, item: R):
        if item in self._items:
            del self._items[item]

    def __contains__(self, x) -> bool:
        return x in self._items

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[R]:
        return iter(self._items.keys())

    def __str__(self):
        return f"{{{', '.join(str(item) for item in self)}}}"
