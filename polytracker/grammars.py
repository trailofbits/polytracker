import json

from typing import BinaryIO, Dict, IO, ItemsView, Iterable, Iterator, List, Optional, Tuple, Union

from .cfg import DiGraph, non_disjoint_union_all

from .mimid.treeminer import attach_comparisons, indexes_to_children, last_comparisons, no_overlap, wrap_terminals


class BasicBlockInvocation:
    def __init__(self, method_call_id: int, name: Optional[str], children: Iterable[int]):
        self.id: int = method_call_id
        self.name: Optional[str] = name
        self.children: List[int] = list(children)

    def __hash__(self):
        return self.id

    def __eq__(self, other):
        return self.id == other.id

    def __len__(self):
        return 2

    def __contains__(self, item):
        return item in (0, 1, 2)

    def __getitem__(self, item: int) -> Union[int, Optional[str], List[int]]:
        if item == 0:
            return self.id
        elif item == 1:
            return self.name
        elif item == 2:
            return self.children
        else:
            raise ValueError(item)

    def __iter__(self) -> Iterable[Union[int, Optional[str], List[int]]]:
        return iter((self.id, self.name, self.children))


class Comparison:
    def __init__(self, idx: int, char: Union[int, str, bytes], method_call_id: int):
        self.idx: int = idx
        if isinstance(char, bytes):
            if len(char) != 1:
                raise ValueError(f"char must be a single character")
            self.char: bytes = char
        elif isinstance(char, str):
            if len(char) != 1:
                raise ValueError(f"char must be a single character")
            self.char = bytes([ord(char[0])])
        else:
            self.char = bytes([char])
        self.method_call_id: int = method_call_id

    def __len__(self):
        return 3

    def __contains__(self, item):
        return item in (0, 1, 2)

    def __getitem__(self, item: int) -> Union[int, bytes]:
        if item == 0:
            return self.idx
        elif item == 1:
            return self.char
        elif item == 2:
            return self.method_call_id
        else:
            raise KeyError(item)

    def __iter__(self) -> Iterable[Union[int, bytes, int]]:
        return iter((self.idx, self.char, self.method_call_id))


class PolyTrackerTrace:
    def __init__(self, methods: Iterable[BasicBlockInvocation], comparisons: Iterable[Comparison], inputstr: bytes):
        self.method_map: Dict[int, BasicBlockInvocation] = {method.id: method for method in methods}
        self.comparisons = list(comparisons)
        self.inputstr = inputstr
        self._cfg: Optional[DiGraph[BasicBlockInvocation]] = None

    @property
    def cfg(self) -> DiGraph[BasicBlockInvocation]:
        if self._cfg is None:
            self._cfg = DiGraph()
            for bb in self.method_map.values():
                self._cfg.add_node(bb)
            for bb in self.method_map.values():
                for child in bb.children:
                    self._cfg.add_edge(bb, self.method_map[child])
        return self._cfg

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

    def __contains__(self, item):
        return item in ("comparisons_fmt", "comparisons", "method_map_fmt", "method_map")

    def __getitem__(self, item: str) -> Union[str, Dict[int, BasicBlockInvocation], List[Comparison], bytes]:
        if item == "comparisons_fmt":
            return "idx, char, method_call_id"
        elif item == "method_map_fmt":
            return "method_call_id, method_name, children"
        elif item == "method_map":
            return self.method_map
        elif item == "comparisons":
            return self.comparisons
        elif item == "inputstr":
            return self.inputstr
        else:
            raise KeyError(item)

    @staticmethod
    def parse(trace_file: IO, input_file: Optional[BinaryIO] = None) -> "PolyTrackerTrace":
        try:
            data = json.load(trace_file)
        except json.decoder.JSONDecodeError as de:
            raise ValueError(f"Error parsing PolyTracker JSON file {trace_file.name}", de)
        if "trace" not in data:
            raise ValueError(f"File {trace_file.name} was not recorded with POLYTRACE=1!")
        trace = data["trace"]

        if 'inputstr' not in trace:
            if input_file is None:
                raise ValueError("Either the input trace must include the 'inputstr' field, or an `input_file` argument"
                                 "must be provided")
            else:
                inputstr: bytes = input_file.read()
        else:
            inputstr: bytes = bytes(trace['inputstr'])

        # mimid expects the first method (ID 0) to have a null method name, so transform the trace to correspond.
        # first, increase all of the method IDs by 1
        mmap_fmt = {field.strip(): idx for idx, field in enumerate(trace["method_map_fmt"].split(","))}
        mmap = trace["method_map"]
        cmp_fmt = {field.strip(): idx for idx, field in enumerate(trace["comparisons_fmt"].split(","))}
        cmp = trace["comparisons"]

        comparisons = [
            Comparison(
                idx=comparison[cmp_fmt["idx"]],
                char=comparison[cmp_fmt["char"]],
                method_call_id=comparison[cmp_fmt["method_call_id"]] + 1,
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
        transformed = PolyTrackerTrace(methods=methods, comparisons=comparisons, inputstr=inputstr)
        assert 0 not in transformed.method_map
        transformed.method_map[0] = BasicBlockInvocation(0, None, [1])
        return transformed


class MethodTree:
    class Node:
        def __init__(self, tree: 'MethodTree', uid: int, name: str):
            self.tree = tree
            self.id: int = uid
            self.name: str = name
            self.indexes: List = []
            self.children: List[int] = []

        class ChildView:
            def __init__(self, node: 'MethodTree.Node'):
                self.node: MethodTree.Node = node

            def __len__(self):
                return len(self.node.children)

            def __getitem__(self, index: int):
                return self.node.tree.nodes_by_id[self.node.children[index]]

            def __iter__(self) -> Iterable['MethodTree.Node']:
                for child in self.node.children:
                    yield self.node.tree.nodes_by_id[child]

        def __getitem__(self, key: str) -> Union[int, str, List, 'MethodTree.Node.ChildView']:
            if key == 'name':
                return self.name
            elif key == 'id':
                return self.id
            elif key == 'indexes':
                return self.indexes
            elif key == 'children':
                return MethodTree.Node.ChildView(self)
            else:
                raise KeyError(key)

        def get(self, key: str, default: Union[int, str, List, 'MethodTree.Node.ChildView'] = None) -> Optional[Union[
            int, str, List, 'MethodTree.Node.ChildView'
        ]]:
            try:
                return self[key]
            except KeyError:
                return default

    def __init__(self):
        self.first_node: int = 0
        self.nodes_by_id: Dict[int, MethodTree.Node] = {}

    def __getitem__(self, uid: int) -> 'MethodTree.Node':
        return self.nodes_by_id[uid]

    def __contains__(self, uid: int):
        return uid in self.nodes_by_id

    def __len__(self):
        return len(self.nodes_by_id)

    def __iter__(self):
        return iter(self.nodes_by_id)

    def items(self) -> ItemsView[int, 'MethodTree.Node']:
        return self.nodes_by_id.items()


def reconstruct_method_tree(*traces: PolyTrackerTrace) -> MethodTree:
    if not traces:
        raise ValueError("At least one trace is required to reconstruct the method tree!")
    unified_graph: DiGraph[BasicBlockInvocation] = non_disjoint_union_all(*(trace.cfg for trace in traces))
    tree = unified_graph.dominator_forest
    if len(tree.roots) != 1:
        raise ValueError("The unified dominator forest has multiple roots!"
                         "This probably means one of the input traces was disconnected.")
    tree_map: MethodTree = MethodTree()
    first_node: Optional[BasicBlockInvocation] = None
    for n in tree.nodes:
        if first_node is None or first_node.id > n.id:
            first_node = n
        assert n.id not in tree_map
        tree_map.nodes_by_id[n.id] = MethodTree.Node(tree_map, n.id, n.name)
    for n1, n2 in tree.edges:
        tree_map.nodes_by_id[n1.id].children.append(n2.id)
    tree_map.first_node = first_node.id

    return tree_map


class Tree:
    def __init__(self, node: MethodTree.Node, parent: Optional['Tree'] = None):
        self.method_name: str = ("<%s>" % node['name']) if node['name'] is not None else '<START>'
        self.indexes = node['indexes']
        self.node_children: List[Union[Tree, Tuple[int, list, int, int]]] = []
        self.remaining_children: Iterator[MethodTree.Node] = iter(node.get('children', []))
        self.parent: Optional[Tree] = parent
        self.start_idx: Optional[int] = None
        self.end_idx: Optional[int] = None

    def __iter__(self) -> Iterator[Union[str, List[Union['Tree', Tuple[int, list, int, int]]], int]]:
        return iter((self.method_name, self.node_children, self.start_idx, self.end_idx))

    def __getitem__(self, idx: Union[int, slice]):
        if isinstance(idx, slice):
            if idx.step is None:
                step = 1
            else:
                step = idx.step
            return [self[i] for i in range(idx.start, idx.stop, step)]
        elif idx == 0:
            return self.method_name
        elif idx == 1:
            return self.node_children
        elif idx == 2:
            return self.start_idx
        elif idx == 3:
            return self.end_idx
        else:
            raise KeyError(idx)

    def __len__(self):
        return 4


def to_tree(node: MethodTree.Node, my_str: bytes) -> Tree:
    root: Tree = Tree(node)
    call_stack: List[Tree] = [root]

    while call_stack:
        t = call_stack[-1]
        try:
            next_child = MethodTree.Node = next(t.remaining_children)
            call_stack.append(Tree(next_child, parent=t))
            continue
        except StopIteration:
            pass
        call_stack.pop()
        idx_children = indexes_to_children(t.indexes, my_str)
        children = no_overlap(t.node_children + idx_children)
        if not children:
            continue
        t.start_idx = children[0][2]
        t.end_idx = children[-1][3]
        si = t.start_idx
        my_children = []
        # FILL IN chars that we did not compare. This is likely due to an i + n
        # instruction.
        for c in children:
            if c[2] != si:
                sbs = my_str[si: c[2]]
                my_children.append((sbs, [], si, c[2] - 1))
            my_children.append(c)
            si = c[3] + 1

        t.node_children = my_children

        if t.parent is not None:
            t.parent.node_children.append(t)

    return root


def miner(traces: List[PolyTrackerTrace]):
    my_trees = []
    for trace in traces:

        # # The following code caches the method tree for debugging purposes only:
        # import os
        # import pickle
        # CACHE_FILE = os.path.join(os.path.dirname(os.path.realpath(__file__)), "method_tree.cache")
        # if os.path.exists(CACHE_FILE):
        #     with open(CACHE_FILE, 'rb') as f:
        #         method_tree = pickle.load(f)
        # else:
        #     method_tree = reconstruct_method_tree(trace)
        #     with open(CACHE_FILE, 'wb') as f:
        #         pickle.dump(method_tree, f)

        method_tree = reconstruct_method_tree(trace)

        comparisons = trace['comparisons']
        attach_comparisons(method_tree, last_comparisons(comparisons))
        my_str = trace.inputstr

        # print("INPUT:", my_str, file=sys.stderr)
        tree = to_tree(method_tree[method_tree.first_node], my_str)
        tree_ = wrap_terminals(tree)
        # print("RECONSTRUCTED INPUT:", tree_to_string(tree), file=sys.stderr)
        my_tree = {'tree': tree_}#, 'original': call_trace['original'], 'arg': call_trace['arg']}
        #assert util.tree_to_str(tree) == my_str
        my_trees.append(my_tree)

    return my_trees


def extract(traces: List[PolyTrackerTrace]):
    return miner(traces)

    #return miner(traces)
