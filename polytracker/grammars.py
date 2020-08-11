from typing import Any, Dict, ItemsView, Iterable, Iterator, List, Optional, Tuple, Union

from .cfg import DiGraph, non_disjoint_union_all

from .mimid.treeminer import attach_comparisons, indexes_to_children, last_comparisons, no_overlap, wrap_terminals
from .mimid.grammarminer import check_empty_rules, collapse_rules, convert_spaces_in_keys, merge_grammar, to_grammar
from .mimid import grammartools
from .tracing import PolyTrackerTrace, BasicBlockInvocation


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
