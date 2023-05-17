from typing import Dict, FrozenSet, Generic, Hashable, Iterable, Iterator, List, Optional, Tuple, Type, TypeVar

T = TypeVar("T", bound=Hashable)
C = TypeVar("C")


class DisjointSet(Generic[T]):
    def __init__(self, initial_elements: Iterable[T] = ()):
        self._counts: Dict[int, int] = {}
        self._parents: Dict[int, int] = {}
        self._elements: List[T] = []
        self._indexes_by_element: Dict[T, int] = {}
        self.update(initial_elements)

    def __len__(self):
        return len(self._elements)

    def __iter__(self) -> Iterator[T]:
        yield from self._elements

    def __contains__(self, item: T):
        return self.find(item) is not None

    def __bool__(self):
        return bool(self._elements)

    def __eq__(self, other):
        if isinstance(other, DisjointSet):
            return frozenset(self.subsets()) == frozenset(other.subsets())
        elif isinstance(other, set) or isinstance(other, frozenset):
            if not other:
                return not self
            subsets = self.subsets()
            return len(subsets) == 1 and subsets[0] == other
        else:
            return False

    def subsets(self) -> Tuple[FrozenSet[T], ...]:
        ret: List[List[T]] = [[] for _ in range(len(self))]
        for i, element in enumerate(self._elements):
            cluster_index = self._indexes_by_element[self.find(element)]
            ret[cluster_index].append(element)
        return tuple(map(frozenset, (s for s in ret if len(s) > 0)))

    def add(self, element: T) -> T:
        """Adds a new element to this set and return the root element of the disjoint set containing the element.

        If the element is new, then return the element itself.
        If the element already exists in the set, then return the root ancestor element of this element.
        """
        existing = self.find(element)
        if existing is None:
            index = len(self._elements)
            self._elements.append(element)
            self._counts[index] = 1
            self._indexes_by_element[element] = index
            self._parents[index] = index
            existing = element
        return existing

    def update(self, *elements: Iterable[T], union: bool = False):
        """Adds all of the elements in the given iterables.

        If union is True, then union all of the elements in each iterable.
        """
        for element_seq in elements:
            first: Optional[T] = None
            for element in element_seq:
                if first is None or not union:
                    first = self.add(element)
                else:
                    self.union(first, element)

    def find(self, element: T) -> Optional[T]:
        """Returns the root ancestor element of the disjoint subset containing element,
        or None if element is not a member of this set"""
        if element not in self._indexes_by_element:
            return None
        stack = [self._indexes_by_element[element]]
        parent = self._parents[stack[-1]]
        while parent != stack[-1]:
            stack.append(parent)
            parent = self._parents[parent]
        for i in stack:
            self._parents[i] = parent
        return self._elements[parent]

    def union(self, element1: T, element2: T) -> T:
        """Unions the disjoint subsets of the two elements.

        The elements will be added to this disjoint set if they are not already members.
        If the elements are already in the same disjoint subset, then the union will do nothing.

        Returns the root element of the disjoint subset resulting from the union.
        """
        ancestor1 = self.add(element1)
        ancestor2 = self.add(element2)
        if ancestor1 != ancestor2:
            id1 = self._indexes_by_element[ancestor1]
            id2 = self._indexes_by_element[ancestor2]
            count1 = self._counts[id1]
            count2 = self._counts[id2]
            if count1 < count2 or (count1 == count2 and id2 < id1):
                ancestor1, ancestor2, id1, id2, count1, count2 = ancestor2, ancestor1, id2, id1, count2, count1
            self._counts[id1] = count1 + count2
            del self._counts[id2]
            self._parents[id2] = id1
        return ancestor1

    def __str__(self):
        contents = " | ".join(
            (", ".join(map(repr, sorted(subset, key=lambda t: self._indexes_by_element[t]))))
            for subset in self.subsets()
        )
        return f"{{{contents}}}"

    @classmethod
    def from_subsets(cls: Type[C], subsets: Iterable[Iterable[T]]) -> C:
        ret = cls()
        ret.update(*subsets, union=True)
        return ret

    def __repr__(self):
        return f"{self.__class__.__name__}.from_subsets({[set(s) for s in self.subsets()]!r})"
