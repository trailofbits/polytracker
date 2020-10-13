from typing import Any, Callable, Generic, Optional, TypeVar


R = TypeVar("R")


class Memoized(Generic[R]):
    def __init__(self, func: Callable[[Any, ...], R]):
        self.func = func
        self._set: bool = False
        self.cached: Optional[R] = None

    def __call__(self, *args, **kwargs) -> R:
        if not self._set:
            self._set = True
            self.cached = self.func(*args, **kwargs)
        return self.cached


def memoize(func: Callable[[Any, ...], R]) -> Callable[[Any, ...], R]:
    return Memoized(func)
