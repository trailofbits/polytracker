import os
import struct
from typing import List, Set
from typing_extensions import Final

"""
This "Final" type means this is just a const
The 8 comes from two uint32_t's representing a nodes parents
"""
TAINT_NODE_SIZE: Final[int] = 8


class TaintForest:
    def __init__(self, path: str):
        self.path: str = path
        self.num_nodes: int = 0  # this is set in self.validate()
        self.validate()

    def validate(self):
        if not os.path.exists(self.path):
            raise ValueError(f"Taint forest file does not exist: {self.path}")
        filesize = os.stat(self.path).st_size
        if filesize % TAINT_NODE_SIZE != 0:
            raise ValueError(f"Taint forest is not a multiple of {TAINT_NODE_SIZE} bytes!")
        self.num_nodes = filesize // TAINT_NODE_SIZE

    def tainted_bytes(self, *labels: int) -> Set[int]:
        # reverse the labels to reduce the likelihood of reproducing work
        node_stack: List[int] = sorted(list(set(labels)), reverse=True)
        history: Set[int] = set(node_stack)
        taints = set()
        with open(self.path, "rb") as forest:
            while node_stack:
                label = node_stack.pop()
                forest.seek(TAINT_NODE_SIZE * label)
                parent1, parent2 = struct.unpack("=II", forest.read(TAINT_NODE_SIZE))
                if parent1 == 0:
                    assert parent2 == 0
                    taints.add(label)
                else:
                    if parent1 not in history:
                        history.add(parent1)
                        node_stack.append(parent1)
                    if parent2 not in history:
                        history.add(parent2)
                        node_stack.append(parent2)
        return taints
