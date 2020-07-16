import json

from typing import Dict, Iterable, List, Optional, TextIO, Tuple, Union

from .mimid.treeminer import miner


class BasicBlockInvocation:
    def __init__(self, method_call_id: int, name: Optional[str], children: Iterable[int]):
        self.id = method_call_id
        self.name: Optional[str] = name
        self.children: List[int] = list(children)

    def __len__(self):
        return 2

    def __getitem__(self, item: int):
        if item == 0:
            return self.id
        elif item == 1:
            return self.name
        elif item == 2:
            return self.children
        else:
            raise ValueError(item)


class Comparison:
    def __init__(self, idx: int, char: Union[int, str, bytes], method_call_id: BasicBlockInvocation):
        self.idx: int = idx
        if isinstance(char, bytes):
            if len(char) != 1:
                raise ValueError(f"char must be a single character")
            self.char: bytes = char
        elif isinstance(char, str):
            if len(char) != 1:
                raise ValueError(f"char must be a single character")
            self.char: bytes = bytes([ord(char[0])])
        else:
            self.char: bytes = bytes([char])
        self.method_call_id: BasicBlockInvocation = method_call_id

    def __len__(self):
        return 3

    def __getitem__(self, item: int):
        if item == 0:
            return self.idx
        elif item == 1:
            return self.char
        elif item == 2:
            return self.method_call_id
        else:
            raise KeyError(item)


class PolyTrackerTrace:
    def __init__(self, methods: Iterable[BasicBlockInvocation], comparisons: Iterable[Comparison]):
        self.method_map: Dict[int, BasicBlockInvocation] = {
            method.id: method
            for method in methods
        }
        self.comparisons = list(comparisons)

    def cfg_roots(self) -> Tuple[int, ...]:
        roots = set(self.method_map.keys()) - {0}
        for m in self.method_map.values():
            if m.id == 0:
                # Do not count our pseudo-root that is required by Mimid
                continue
            roots -= set(m.children)
        return tuple(roots)

    def is_cfg_connected(self) -> bool:
        return len(self.cfg_roots()) == 1

    def __len__(self):
        return 4

    def __getitem__(self, item: str):
        if item == "comparisons_fmt":
            return "idx, char, method_call_id"
        elif item == "method_map_fmt":
            return "method_call_id, method_name, children"
        elif item == "method_map":
            return self.method_map
        elif item == "comparisons":
            return self.comparisons
        else:
            raise KeyError(item)

    @staticmethod
    def parse(trace_file: TextIO) -> 'PolyTrackerTrace':
        try:
            data = json.load(trace_file)
        except json.decoder.JSONDecodeError as de:
            raise ValueError(f"Error parsing PolyTracker JSON file {trace_file.name}", de)
        if "trace" not in data:
            raise ValueError(f"File {trace_file.name} was not recorded with POLYTRACE=1!")
        trace = data["trace"]

        # mimid expects the first method (ID 0) to have a null method name, so transform the trace to correspond.
        # first, increase all of the method IDs by 1
        mmap_fmt = {field.strip(): idx for idx, field in enumerate(trace["method_map_fmt"].split(','))}
        mmap = trace["method_map"]
        cmp_fmt = {field.strip(): idx for idx, field in enumerate(trace["comparisons_fmt"].split(','))}
        cmp = trace["comparisons"]

        comparisons = [
            Comparison(
                idx=comparison[cmp_fmt["idx"]],
                char=comparison[cmp_fmt["char"]],
                method_call_id=comparison[cmp_fmt["method_call_id"]] + 1
            )
            for comparison in cmp
        ]
        methods = [
            BasicBlockInvocation(
                method_call_id=mapping[mmap_fmt["method_call_id"]] + 1,
                name=mapping[mmap_fmt["method_name"]],
                children=[cid + 1 for cid in mapping[mmap_fmt["children"]]],
            )
            for mapping in mmap.values()
        ]
        transformed = PolyTrackerTrace(methods=methods, comparisons=comparisons)
        assert 0 not in transformed.method_map
        transformed.method_map[0] = BasicBlockInvocation(0, None, [1])
        return transformed


def parse_polytracker_trace(trace_file: TextIO) -> Dict:
    try:
        data = json.load(trace_file)
    except json.decoder.JSONDecodeError as de:
        raise ValueError(f"Error parsing PolyTracker JSON file {trace_file.name}", de)
    if "trace" not in data:
        raise ValueError(f"File {trace_file.name} was not recorded with POLYTRACE=1!")
    trace = data["trace"]

    # mimid expects the first method (ID 0) to have a null method name, so transform the trace to correspond.
    # first, increase all of the method IDs by 1
    mmap_fmt = {field.strip(): idx for idx, field in enumerate(trace["method_map_fmt"].split(','))}
    mmap = trace["method_map"]
    cmp_fmt = {field.strip(): idx for idx, field in enumerate(trace["comparisons_fmt"].split(','))}
    cmp = trace["comparisons"]
    transformed = {
        "comparisons_fmt": "idx, char, method_call_id",
        "comparisons": [
            [comparison[cmp_fmt["idx"]], comparison[cmp_fmt["char"]], comparison[cmp_fmt["method_call_id"]] + 1]
            for comparison in cmp
        ],
        "method_map_fmt": "method_call_id, method_name, children",
        "method_map": {
            int(method_id) + 1: [
                mapping[mmap_fmt["method_call_id"]] + 1,
                mapping[mmap_fmt["method_name"]],
                [cid + 1 for cid in mapping[mmap_fmt["children"]]],
            ]
            for method_id, mapping in mmap.items()
        },
    }
    # lastly, add a new null method with ID 0
    assert "0" not in transformed["method_map"]
    transformed["method_map"][0] = [0, None, [1]]

    return transformed


def extract(traces: List[Dict]):
    return miner(traces)
