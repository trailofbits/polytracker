import json

from typing import Any, BinaryIO, Dict, IO, ItemsView, Iterable, Iterator, List, Optional, Tuple, Union

from .cfg import DiGraph, non_disjoint_union_all

from .mimid.treeminer import attach_comparisons, indexes_to_children, last_comparisons, no_overlap, wrap_terminals
from .mimid.grammarminer import check_empty_rules, collapse_rules, convert_spaces_in_keys, merge_grammar, to_grammar
from .mimid import grammartools


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


class TreeNode:
    def __init__(self, tree: 'MethodTree', uid: int, name: str):
        self.tree: MethodTree = tree
        self.id: int = uid
        self.name: str = name
        self.indexes: List = []
        self.children: List[int] = []

    class ChildView:
        def __init__(self, node: 'TreeNode'):
            self.node: TreeNode = node

        def __len__(self):
            return len(self.node.children)

        def __getitem__(self, index: int):
            return self.node.tree.nodes_by_id[self.node.children[index]]

        def __iter__(self) -> Iterable['TreeNode']:
            for child in self.node.children:
                yield self.node.tree.nodes_by_id[child]

    def __getitem__(self, key: str) -> Union[int, str, List, 'TreeNode.ChildView']:
        if key == 'name':
            return self.name
        elif key == 'id':
            return self.id
        elif key == 'indexes':
            return self.indexes
        elif key == 'children':
            return TreeNode.ChildView(self)
        else:
            raise KeyError(key)

    def get(self, key: str, default: Union[int, str, List, 'TreeNode.ChildView'] = None) -> Optional[Union[
        int, str, List, 'TreeNode.ChildView'
    ]]:
        try:
            return self[key]
        except KeyError:
            return default


class MethodTree:
    def __init__(self):
        self.first_node: int = 0
        self.nodes_by_id: Dict[int, TreeNode] = {}

    def __getitem__(self, uid: int) -> TreeNode:
        return self.nodes_by_id[uid]

    def __contains__(self, uid: int):
        return uid in self.nodes_by_id

    def __len__(self):
        return len(self.nodes_by_id)

    def __iter__(self):
        return iter(self.nodes_by_id)

    def items(self) -> ItemsView[int, TreeNode]:
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
        tree_map.nodes_by_id[n.id] = TreeNode(tree_map, n.id, n.name)
    for n1, n2 in tree.edges:
        tree_map.nodes_by_id[n1.id].children.append(n2.id)
    tree_map.first_node = first_node.id

    return tree_map


class Tree:
    def __init__(self, node: TreeNode, parent: Optional['Tree'] = None):
        self.method_name: str = ("<%s>" % node['name']) if node['name'] is not None else '<START>'
        self.indexes = node['indexes']
        self.node_children: List[Union[Tree, Tuple[int, list, int, int]]] = []
        self.remaining_children: Iterator[TreeNode] = iter(node.get('children', []))
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


def to_tree(node: TreeNode, my_str: bytes) -> Tree:
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


def miner(traces: Iterable[PolyTrackerTrace]) -> Iterable[Tuple]:
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

        tree = to_tree(method_tree[method_tree.first_node], my_str)
        yield wrap_terminals(tree)


def convert_to_grammar(my_trees):
    grammar = {}
    ret = []
    for my_tree in my_trees:
        tree = my_tree['tree']
        start = tree[0]
        ret.append(start)
        g = to_grammar(tree, grammar)
        grammar = merge_grammar(grammar, g)
    return ret, grammar


class Terminal:
    def __init__(self, terminal: Union[bytes, str]):
        if isinstance(terminal, str):
            terminal = terminal.encode('utf-8')
        self.terminal: bytes = terminal

    def __repr__(self):
        return f"{self.__class__.__name__}(terminal={self.terminal!r})"

    def __str__(self):
        ret = '"'
        for i in self.terminal:
            if i == ord('\n'):
                b = "\\n"
            elif i == ord('\t'):
                b = "\\t"
            elif i == ord('\r'):
                b = "\\r"
            elif i == ord('"'):
                b = '\\"'
            elif i == ord('\\'):
                b = '\\\\'
            elif ord(" ") <= i <= ord("~"):
                b = chr(i)
            else:
                b = f"\\x{i:02x}"
            ret = f"{ret}{b}"
        return f"{ret}\""


class Rule:
    def __init__(self, grammar: 'Grammar', *alternatives: Union[Terminal, str]):
        self.grammar: Grammar = grammar
        self.alternatives: Tuple[Union[Terminal, str], ...] = tuple(alternatives)

    @staticmethod
    def load(grammar: 'Grammar', *alternatives: str) -> 'Rule':
        alts = []
        for a in alternatives:
            if isinstance(a, str) and a.startswith('<') and a.endswith('>'):
                alts.append(a)
            else:
                alts.append(Terminal(a))
        return Rule(grammar, *alts)

    def __iter__(self) -> Iterable[Union[Terminal, 'Production']]:
        for alternative in self.alternatives:
            if isinstance(alternative, Terminal):
                yield alternative
            else:
                yield self.grammar[alternative]

    def __len__(self):
        return len(self.alternatives)

    def __str__(self):
        return " ".join(map(str, self.alternatives))


class Production:
    def __init__(self, grammar: 'Grammar', name: str, *rules: Rule):
        if name in grammar:
            raise ValueError(f"A production named {name!r} already exists in grammar {grammar!s}!")
        self.grammar: Grammar = grammar
        self.name: str = name
        self.rules: Tuple[Rule, ...] = tuple(rules)
        grammar.productions[name] = self

    @staticmethod
    def load(grammar: 'Grammar', name: str, *rules: Iterable[str]) -> 'Production':
        return Production(grammar, name, *(Rule.load(grammar, *alternatives) for alternatives in rules))

    def __iter__(self) -> Iterable[Rule]:
        return iter(self.rules)

    def __len__(self):
        return len(self.rules)

    def __str__(self):
        rules = ' | '.join(map(str, self.rules))
        return f"{self.name} ::= {rules}"


class Grammar:
    def __init__(self):
        self.productions: Dict[str, Production] = {}
        self.start: Optional[Production] = None

    def load(self, raw_grammar: Dict[str, Any]):
        for name, definition in raw_grammar.items():
            Production.load(self, name, *definition)

    def __len__(self):
        return len(self.productions)

    def __iter__(self) -> Iterable[Production]:
        yield from self.productions.values()

    def __getitem__(self, production_name: str):
        return self.productions[production_name]

    def __contains__(self, production_name: str):
        return production_name in self.productions

    def __str__(self):
        return '\n'.join(map(str, self.productions.values()))


def extract(traces: List[PolyTrackerTrace]) -> Grammar:
    trees = [{'tree': list(tree)} for tree in miner(traces)]
    #gmethod_trees = generalize_method_trees(trees)
    #print(json.dumps(gmethod_trees, indent=4))
    ret, g = convert_to_grammar(trees)
    assert len(set(ret)) == 1
    start_symbol = ret[0]
    g = grammartools.grammar_gc(g, start_symbol)  # garbage collect
    g = check_empty_rules(g)  # add optional rules
    g = grammartools.grammar_gc(g, start_symbol)  # garbage collect
    g = collapse_rules(g)  # learn regex
    g = grammartools.grammar_gc(g, start_symbol)  # garbage collect
    g = convert_spaces_in_keys(g)  # fuzzable grammar
    g = grammartools.grammar_gc(g, start_symbol)  # garbage collect
    g = grammartools.compact_grammar(g, start_symbol)
    ret = Grammar()
    ret.load(g)
    return ret
