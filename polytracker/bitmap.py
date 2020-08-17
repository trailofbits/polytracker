from abc import ABCMeta
from typing import cast, Dict, FrozenSet, Optional, Type, TypeVar, ValuesView


class BitmapValue:
    def __init__(self, value: int, name: Optional[str] = None):
        self.value: int = value
        self.name: Optional[str] = name


class BitmapMeta(ABCMeta):
    def __init__(cls, name, bases, clsdict):
        if name != "Bitmap":
            types = {}
            setattr(cls, "type_map", types)
            for member_name, value in clsdict.items():
                if isinstance(value, BitmapValue):
                    inst = cls(value=value.value)
                    if value.name is None:
                        name = member_name
                    else:
                        name = value.name
                    clsdict[member_name] = inst
                    types[name] = inst
        super().__init__(name, bases, clsdict)


B = TypeVar("B", bound='Bitmap')


class Bitmap(metaclass=BitmapMeta):
    type_map: Dict[str, "Bitmap"] = {}

    def __init__(self, value: int):
        if self.__class__ == Bitmap.__class__:
            raise ValueError("You cannot instantiate a Bitmap object directly; it must be subclassed!")
        self.value = value

    @classmethod
    def get(cls: Type[B], name: str) -> Optional[B]:
        return cast(B, cls.type_map.get(name, None))

    @classmethod
    def types(cls: Type[B]) -> ValuesView[B]:
        return cast(ValuesView[B], cls.type_map.values())

    def names(self) -> FrozenSet[str]:
        t = []
        for name, bitmap in self.type_map.items():
            if bitmap in self:
                t.append(name)
        return frozenset(t)

    def __and__(self: B, other: B) -> B:
        return self.__class__(value=self.value & other.value)

    def __rand__(self: B, other: B) -> B:
        self.value &= other.value
        return self

    def __or__(self: B, other: B) -> B:
        return self.__class__(value=self.value | other.value)

    def __ror__(self: B, other: B) -> B:
        self.value |= other.value
        return self

    def __xor__(self: B, other: B) -> B:
        return self.__class__(value=self.value ^ other.value)

    def __rxor__(self: B, other: B) -> B:
        self.value ^= other.value
        return self

    def __hash__(self):
        return self.value

    def __eq__(self, other):
        return isinstance(other, Bitmap) and other.value == self.value

    def __contains__(self, bitmap: "Bitmap") -> bool:
        return bool(bitmap.value & self.value)

    def __bool__(self):
        return self.value != 0

    def __repr__(self):
        return f"{self.__class__.__name__}(value={self.value!r})"

    def __str__(self):
        names = self.names()
        if not names:
            return repr(self)
        elif len(names) == 1:
            return next(iter(names))
        else:
            return f"<{', '.join(names)}>"
