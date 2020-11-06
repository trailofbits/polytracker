from collections import OrderedDict
from collections.abc import MutableSet as AbstractMutableSet, MutableMapping
from typing import Callable, Generic, Optional, TypeVar, Iterator

R = TypeVar("R")
V = TypeVar("V")


class Memoized(Generic[R]):
    def __init__(self, func: Callable[..., R]):
        self.func = func
        self._set: bool = False
        self.cached: Optional[R] = None

    def __call__(self, *args, **kwargs) -> R:
        if not self._set:
            self._set = True
            self.cached = self.func(*args, **kwargs)
        return self.cached  # type: ignore


def memoize(func: Callable[..., R]) -> Callable[..., R]:
    return Memoized(func)


class OrderedSet(Generic[R], AbstractMutableSet):  # type: ignore
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


class LRUCache(Generic[R, V], MutableMapping):
    def __init__(self, max_size: Optional[int] = None):
        self._items: OrderedDict[R, V] = OrderedDict()
        self.max_size: Optional[int] = max_size

    def __getitem__(self, k: R) -> V:
        ret = self._items[k]
        self._items.move_to_end(k, last=True)
        return ret

    def __setitem__(self, k: R, v: V) -> None:
        self._items[k] = v
        while self.max_size is not None and len(self._items) > self.max_size:
            self._items.popitem(last=False)

    def __delitem__(self, k: R) -> None:
        del self._items[k]

    def __len__(self) -> int:
        return len(self._items)

    def __iter__(self) -> Iterator[R]:
        for key in self._items:
            self._items.move_to_end(key, last=True)
            yield key
