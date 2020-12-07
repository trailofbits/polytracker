import os
import struct
from typing import Dict, FrozenSet, Iterator, List, Optional, Set
from typing_extensions import Final

from tqdm import tqdm, trange

from .cache import LRUCache
from .cfg import DAG

"""
This "Final" type means this is just a const
The 8 comes from two uint32_t's representing a nodes parents
"""
TAINT_NODE_SIZE: Final[int] = 8


class TaintForest:
    def __init__(self, path: str, canonical_mapping: Optional[Dict[int, int]] = None):
        self.path: str = path
        if canonical_mapping is None:
            canonical_mapping = {}
        self.canonical_mapping: Dict[int, int] = canonical_mapping
        self.num_nodes: int = 0  # this is set in self.validate()
        self.validate()

    def to_graph(self) -> DAG[int]:
        dag: DAG[int] = DAG()
        with open(self.path, "rb") as forest:
            for label in trange(self.num_nodes, desc="Traversing the taint forest", leave=False, unit=" labels"):
                dag.add_node(label)
                parent1, parent2 = struct.unpack("=II", forest.read(TAINT_NODE_SIZE))
                if parent1 != 0:
                    dag.add_edge(parent1, label)
                if parent2 != 0:
                    dag.add_edge(parent2, label)
        return dag

    def access_sequence(self, max_cache_size: Optional[int] = None) -> Iterator[FrozenSet[int]]:
        cache: LRUCache[int, FrozenSet[int]] = LRUCache(max_cache_size)
        with open(self.path, "rb") as forest:
            for label in range(self.num_nodes):
                if label == 0:
                    continue
                parent1, parent2 = struct.unpack("=II", forest.read(TAINT_NODE_SIZE))
                if parent1 == 0:
                    assert parent2 == 0
                    if label not in self.canonical_mapping:
                        # raise ValueError(f"Taint label {label} is not in the canonical mapping!")
                        continue
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

    def validate(self, full: bool = False):
        if not os.path.exists(self.path):
            raise ValueError(f"Taint forest file does not exist: {self.path}")
        filesize = os.stat(self.path).st_size
        if filesize % TAINT_NODE_SIZE != 0:
            raise ValueError(f"Taint forest is not a multiple of {TAINT_NODE_SIZE} bytes!")
        self.num_nodes = filesize // TAINT_NODE_SIZE
        if full:
            # ensure that every label's parents are less than its own label value
            with open(self.path, "rb") as forest:
                for label in trange(self.num_nodes, desc="Validating taint forest topology", leave=False, unit=" labels"):
                    parent1, parent2 = struct.unpack("=II", forest.read(TAINT_NODE_SIZE))
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
        with open(self.path, "rb") as forest, tqdm(
            desc=f"finding canonical taints for {labels_str}",
            leave=False,
            bar_format="{l_bar}{bar}| [{elapsed}<{remaining}, {rate_fmt}{postfix}]'",
            total=sum(node_stack),
        ) as t:
            while node_stack:
                label = node_stack.pop()
                t.update(label)
                forest.seek(TAINT_NODE_SIZE * label)
                parent1, parent2 = struct.unpack("=II", forest.read(TAINT_NODE_SIZE))
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
