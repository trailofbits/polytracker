import os
import struct
from typing import Dict, FrozenSet, Iterator, List, Optional, Set, Tuple, Union, BinaryIO
from typing_extensions import Final
import sqlite3
from tqdm import tqdm, trange

from .cache import LRUCache
from .cfg import DAG

"""
This "Final" type means this is just a const
The 8 comes from two uint32_t's representing a nodes parents
"""
TAINT_NODE_SIZE: Final[int] = 8


class TaintForest:
    def __init__(self, path_or_conn, canonical_mapping: Optional[Dict[int, int]] = None, input_id: Optional[int] = None):
        self.path_or_conn: Union[str, sqlite3.Connection] = path_or_conn
        if canonical_mapping is None:
            canonical_mapping = {}
        self.canonical_mapping: Dict[int, int] = canonical_mapping
        self.input_id = input_id
        self.num_nodes: int = 0  # this is set in self.validate()
        self.validate()

    @property
    def forest(self) -> Iterator[Tuple[int, int, int]]:
        if isinstance(self.path_or_conn, str):
            with open(self.path_or_conn, "rb") as forest:
                for label in range(self.num_nodes):
                    if label == 0:
                        continue
                    parent1, parent2 = struct.unpack("=II", forest.read(TAINT_NODE_SIZE))
                    yield parent1, parent2, label
        else:
            # Only query each as needed
            for label in range(self.num_nodes):
                if label == 0:
                    continue
                # Should just be size 1
                query = [item for item in self.path_or_conn.execute("SELECT * FROM taint_forest WHERE label=? AND input_id=?",
                                                                    [label, self.input_id])]
                parent1, parent2 = query[0]
                yield parent1, parent2, label

    @property
    def forest_size(self) -> int:
        if isinstance(self.path_or_conn, str):
            filesize = os.stat(self.path_or_conn).st_size
            if filesize % TAINT_NODE_SIZE != 0:
                raise ValueError(f"Taint forest is not a multiple of {TAINT_NODE_SIZE} bytes!")
            self.num_nodes = filesize // TAINT_NODE_SIZE
            return self.num_nodes
        else:
            query = "SELECT * from taint_forest WHERE input_id=?"
            for x in self.path_or_conn.execute(query, [self.input_id]):
                self.num_nodes += 1
            return self.num_nodes

    def _forest_handle(self) -> Union[BinaryIO, sqlite3.Connection]:
        if isinstance(self.path_or_conn, str):
            with open(self.path_or_conn, "rb") as forest:
                return forest
        else:
            return self.path_or_conn

    def _get_parents(self, handle: Union[BinaryIO, sqlite3.Connection], label: int) -> Tuple[int, int]:
        if isinstance(handle, BinaryIO):
            handle.seek(TAINT_NODE_SIZE * label)
            parent1, parent2 = struct.unpack("=II", handle.read(TAINT_NODE_SIZE))
            return parent1, parent2
        else:
            query = "SELECT parent_one, parent_two FROM taint_forest where label=? AND input_id=?"
            results = [x for x in handle.execute(query, [label, self.input_id])]
            parent1, parent2 = results[0]
            return parent1, parent2

    def to_graph(self) -> DAG[int]:
        dag: DAG[int] = DAG()
        for p1, p2, label in tqdm(self.forest, total=self.num_nodes, desc="Traversing the taint forest", leave=False, unit=" labels"):
            dag.add_node(label)
            if p1 != 0:
                dag.add_edge(p1, label)
            if p2 != 0:
                dag.add_edge(p2, label)
        return dag

    def access_sequence(self, max_cache_size: Optional[int] = None) -> Iterator[FrozenSet[int]]:
        cache: LRUCache[int, FrozenSet[int]] = LRUCache(max_cache_size)
        for parent1, parent2, label in self.forest:
            if label == 0:
                continue
            if parent1 == 0:
                assert parent2 == 0
                if label not in self.canonical_mapping:
                    raise ValueError(f"Taint label {label} is not in the canonical mapping!")
                ret = frozenset([self.canonical_mapping[label]])
            else:
                if parent1 in cache:
                    p1 = cache[parent1]
                else:
                    p1 = frozenset(self.tainted_bytes(parent1))
                    cache[parent1] = p1
                if parent2 in cache:
                    p2 = cache[parent2]
                else:
                    p2 = frozenset(self.tainted_bytes(parent2))
                    cache[parent2] = p2
                ret = p1 | p2
            yield ret
            cache[label] = ret

    def validate_forest_sql(self):
        if self.path_or_conn is None:
            raise ValueError(f"Sqlite3 connection cannot be none!")
        if self.input_id is None:
            raise ValueError(f"Input ID cannot be none when using a sqlite db")

    def validate_forest_file(self):
        if not os.path.exists(self.path_or_conn):
            raise ValueError(f"Taint forest file does not exist: {self.path_or_conn}")
        filesize = os.stat(self.path_or_conn).st_size
        if filesize % TAINT_NODE_SIZE != 0:
            raise ValueError(f"Taint forest is not a multiple of {TAINT_NODE_SIZE} bytes!")

    def validate(self, full: bool = False):
        if isinstance(self.path_or_conn, str):
            self.validate_forest_file()
        else:
            self.validate_forest_sql()

        num_nodes = self.forest_size
        if full:
            for parent1, parent2, label in tqdm(self.forest, total=num_nodes, desc="Validating taint forest topology",
                                                leave=False, unit=" labels"):
                if parent1 == parent2 and parent1 != 0:
                    raise ValueError(f"Taint label {label} has two parents that both have label {parent1}")
                elif parent1 != 0 and parent2 != 0:
                    if parent1 >= label:
                        raise ValueError(f"Taint label {label} has a parent with a higher label: {parent1}")
                    if parent2 >= label:
                        raise ValueError(f"Taint label {label} has a parent with a higher label: {parent1}")
                elif parent1 == 0 and parent2 == 0:
                    if label not in self.canonical_mapping and label != 0:
                        raise ValueError(f"Canonical taint label {label} is missing from the canonical mapping")
                else:
                    raise ValueError(f"Taint label {label} has one non-zero parent and another zero parent")

    def tainted_bytes(self, *labels: int) -> Set[int]:
        # reverse the labels to reduce the likelihood of reproducing work
        node_stack: List[int] = sorted(list(set(labels)), reverse=True)
        history: Set[int] = set(node_stack)
        taints = set()
        if len(labels) < 10:
            labels_str = ", ".join(map(str, labels))
        else:
            labels_str = f"{len(labels)} labels"
        with self._forest_handle() as forest, tqdm(
            desc=f"finding canonical taints for {labels_str}",
            leave=False,
            bar_format="{l_bar}{bar}| [{elapsed}<{remaining}, {rate_fmt}{postfix}]'",
            total=sum(node_stack),
        ) as t:
            while node_stack:
                label = node_stack.pop()
                t.update(label)
                parent1, parent2 = self._get_parents(forest, label)
                if parent1 == 0:
                    assert parent2 == 0
                    if label not in self.canonical_mapping:
                        raise ValueError(f"Taint label {label} is not in the canonical mapping!")
                    taints.add(self.canonical_mapping[label])
                else:
                    if parent1 not in history:
                        history.add(parent1)
                        node_stack.append(parent1)
                        t.total += parent1
                    if parent2 not in history:
                        history.add(parent2)
                        node_stack.append(parent2)
                        t.total += parent2
        return taints
