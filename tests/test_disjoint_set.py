import pytest

from polytracker.disjoint_set import DisjointSet


def test_disjoint_set():
    values = "abcdefghijklmnopqrstuvwxyz"
    ds: DisjointSet[str] = DisjointSet()
    ds.update(values)
    assert len(ds) == 26
    assert (
        str(ds)
        == "{'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm' | 'n' | 'o' | "
        "'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z'}"
    )
    assert all(ds.find(t) == t for t in values)
    assert ds.find("A") is None
    ds.union("a", "b")
    assert ds.find("b") == "a"
    assert ds.find("a") == "a"
    assert (
        str(ds)
        == "{'a', 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm' | 'n' | 'o' | "
        "'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z'}"
    )
    assert DisjointSet.from_subsets(ds.subsets()) == ds
