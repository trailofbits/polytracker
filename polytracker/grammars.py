from abc import ABCMeta, abstractmethod
from argparse import ArgumentParser, Namespace
from collections import defaultdict
import itertools
from logging import getLogger
from typing import (
    Any,
    cast,
    Dict,
    FrozenSet,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)

# TODO remove
import graphviz
import networkx as nx
from tqdm import tqdm, trange

from . import PolyTrackerTrace
from .cfg import DiGraph
from .parsing import (
    highlight_offset,
    ImmutableParseTree,
    MutableParseTree,
    NonGeneralizedParseTree,
    ParseTree,
    Start,
    Terminal,
    trace_to_non_generalized_tree,
)
from .plugins import Command
from .repl import PolyTrackerREPL
from .tracing import (
    BasicBlockEntry,
    FunctionInvocation,
    ProgramTrace,
    TraceEvent,
)

log = getLogger("grammars")


NonTerminal = str
Symbol = Union[NonTerminal, Terminal]


class Rule:
    def __init__(self, grammar: "Grammar", *sequence: Symbol):
        self.grammar: Grammar = grammar
        self.sequence: Tuple[Symbol, ...] = Rule.combine_terminals(sequence)
        self.has_terminals: bool = any(isinstance(t, Terminal) for t in self.sequence)

    @staticmethod
    def combine_terminals(sequence: Iterable[Symbol]) -> Tuple[Symbol, ...]:
        seq: List[Symbol] = []
        for t in sequence:
            if isinstance(t, Terminal):
                if seq and isinstance(seq[-1], Terminal):
                    seq[-1] = seq[-1] + t
                else:
                    seq.append(t)
            else:
                seq.append(t)
        return tuple(seq)

    @property
    def can_produce_terminal(self) -> bool:
        return self.has_terminals or any(p.can_produce_terminal for p in self if isinstance(p, Production))

    def remove_sub_production(self, prod_name: str) -> bool:
        old_len = len(self.sequence)
        self.sequence = Rule.combine_terminals([s for s in self.sequence if s != prod_name])
        return len(self.sequence) != old_len

    def replace_sub_production(self, to_replace: NonTerminal, replace_with: Union[NonTerminal, "Rule"]) -> bool:
        if isinstance(replace_with, NonTerminal):
            if to_replace == replace_with:
                return False
            replacement: List[Symbol] = [replace_with]
        else:
            replacement = list(replace_with.sequence)
        new_seq = []
        modified = False
        for s in self.sequence:
            if s == to_replace:
                new_seq.extend(replacement)
                modified = True
            else:
                new_seq.append(s)
        if modified:
            self.sequence = Rule.combine_terminals(new_seq)
        return modified

    def __hash__(self):
        return hash(self.sequence)

    def __eq__(self, other):
        return self.sequence == other.sequence

    @staticmethod
    def load(grammar: "Grammar", *sequence: Symbol) -> "Rule":
        alts: List[Symbol] = []
        for a in sequence:
            if isinstance(a, NonTerminal):
                if a.startswith("<") and a.endswith(">"):
                    alts.append(a)
                else:
                    alts.append(Terminal(a))
            else:
                alts.append(a)
        return Rule(grammar, *alts)

    def __iter__(self) -> Iterator[Union[Terminal, "Production"]]:
        for alternative in self.sequence:
            if isinstance(alternative, Terminal):
                yield alternative
            else:
                yield self.grammar[alternative]

    def __len__(self):
        return len(self.sequence)

    def __getitem__(self, index):
        return self.sequence[index]

    def __bool__(self):
        return bool(self.sequence)

    def __str__(self):
        if not self.sequence:
            return "ε"
        else:
            return " ".join(map(str, self.sequence))


class Production:
    def __init__(self, grammar: "Grammar", name: str, *rules: Rule):
        if name in grammar:
            raise ValueError(f"A production named {name!r} already exists in grammar {grammar!s}!")
        self.grammar: Grammar = grammar
        self.name: str = name
        self.rules: Set[Rule] = set(rules)
        self.removable: bool = True
        grammar.productions[name] = self
        for rule in rules:
            for term in rule.sequence:
                if isinstance(term, str):
                    grammar.used_by[term].add(name)
        self._can_produce_terminal: Optional[bool] = None

    def first_rule(self) -> Optional[Rule]:
        if self.rules:
            return next(iter(self.rules))
        else:
            return None

    def partial_match(self, sentence: bytes) -> Iterator["PartialMatch"]:
        """Enumerates all partial parse trees and remaining symbols that match the given sentence"""
        if not self.rules or not sentence:
            yield PartialMatch(tree=ImmutableParseTree(self), remaining_symbols=(), remaining_bytes=sentence)
            return
        for rule in self.rules:

            def make_tree() -> Tuple[ParseTree[ParseTreeValue], ParseTree[ParseTreeValue]]:
                root: ParseTree[ParseTreeValue] = ImmutableParseTree(self)
                rtree: ParseTree[ParseTreeValue] = ImmutableParseTree(rule)
                root.children.append(rtree)  # type: ignore
                return root, rtree

            stack: List[Tuple[bytes, List[ParseTree[ParseTreeValue]], List[Symbol]]] = [(sentence, [], list(rule.sequence))]
            while stack:
                remaining_bytes, trees, remaining_symbols = stack.pop()
                if not remaining_symbols or not remaining_bytes:
                    root_tree, rule_tree = make_tree()
                    if not rule_tree.children:
                        if not trees:
                            trees = [ImmutableParseTree(Terminal(""))]
                        rule_tree.children = trees  # type: ignore
                    yield PartialMatch(
                        tree=root_tree, remaining_symbols=tuple(remaining_symbols), remaining_bytes=remaining_bytes
                    )
                else:
                    next_symbol = remaining_symbols[0]
                    if isinstance(next_symbol, Terminal):
                        if remaining_bytes == next_symbol.terminal:
                            root_tree, rule_tree = make_tree()
                            rule_tree.children = trees + [ImmutableParseTree(next_symbol)]  # type: ignore
                            yield PartialMatch(
                                tree=root_tree, remaining_symbols=tuple(remaining_symbols[1:]), remaining_bytes=b""
                            )
                        elif remaining_bytes.startswith(next_symbol.terminal):
                            stack.append(
                                (
                                    remaining_bytes[len(next_symbol.terminal):],
                                    trees + [ImmutableParseTree(next_symbol)],
                                    remaining_symbols[1:],
                                )
                            )
                        else:
                            # the terminal didn't match the input sentence
                            pass
                    else:
                        # this is a non-terminal
                        for match in self.grammar[next_symbol].partial_match(remaining_bytes):
                            if not match.remaining_bytes or (not match.remaining_symbols and len(remaining_symbols) < 2):
                                root_tree, rule_tree = make_tree()
                                rule_tree.children = trees + [match.tree]  # type: ignore
                                yield PartialMatch(
                                    tree=root_tree,
                                    remaining_symbols=tuple(remaining_symbols[1:]),
                                    remaining_bytes=match.remaining_bytes,
                                )
                            else:
                                stack.append(
                                    (
                                        match.remaining_bytes,
                                        trees + [match.tree],
                                        list(match.remaining_symbols) + remaining_symbols[1:],
                                    )
                                )

    def remove_recursive_rules(self) -> Set[Rule]:
        """Removes and returns all rules that solely recursively call this same production"""
        removed = set([rule for rule in self if len(rule) == 1 and rule[0] == self.name])
        self.rules -= removed
        return removed

    @property
    def can_produce_terminal(self) -> bool:
        if self._can_produce_terminal is None:
            queue: List[Production] = [
                prod
                for prod in self.grammar.productions.values()
                if prod._can_produce_terminal is None and any(r.has_terminals for r in prod.rules)
            ]
            visited: Set[Production] = set(queue)
            for p in queue:
                # all nodes in the queue can trivially produce a terminal
                p._can_produce_terminal = True
            with tqdm(leave=False, unit=" productions", desc="finding empty productions") as status:
                while queue:
                    prod = queue.pop()
                    used_by = [used_by_prod for used_by_prod in prod.used_by if used_by_prod not in visited]
                    for used_by_prod in used_by:
                        used_by_prod._can_produce_terminal = True
                    queue.extend(used_by)
                    visited |= set(used_by)
                    status.update(1)
            if self._can_produce_terminal is None:
                self._can_produce_terminal = False
        return self._can_produce_terminal  # type: ignore

    @property
    def used_by(self) -> Iterable["Production"]:
        return (self.grammar[name] for name in self.grammar.used_by[self.name])

    def _propagate_terminals(self):
        """Calculates if this production can produce a terminal.
        If a rule calls another terminal whose _can_produce_terminal member is None, assume that it is False

        """
        if any(r.has_terminals for r in self.rules):
            self._can_produce_terminal = True
        for v in itertools.chain(*self.rules):
            if isinstance(v, Production):
                if v._can_produce_terminal is not None and v._can_produce_terminal:
                    # The rule calls another production that can produce a terminal
                    self._can_produce_terminal = True
                    break
            else:
                # v is a Terminal
                self._can_produce_terminal = True
                break
        else:
            self._can_produce_terminal = False

    def remove_sub_production(self, name: str):
        new_rules = []
        for rule in self.rules:
            rule.remove_sub_production(name)
            if rule:
                new_rules.append(rule)
        self.rules = set(new_rules)
        self.grammar.used_by[name].remove(self.name)

    def replace_sub_production(self, to_replace: NonTerminal, replace_with: Union[NonTerminal, Rule]):
        if isinstance(replace_with, NonTerminal):
            if to_replace == replace_with:
                return
            new_prods: List[NonTerminal] = [replace_with]
            replace_with = Rule(self.grammar, replace_with)
        else:
            new_prods = [v for v in replace_with.sequence if isinstance(v, NonTerminal)]
        modified = False
        for rule in list(self.rules):
            self.rules.remove(rule)
            modified = rule.replace_sub_production(to_replace, replace_with) or modified
            self.rules.add(rule)
        if modified:
            self.grammar.used_by[to_replace].remove(self.name)
            for new_prod in new_prods:
                self.grammar.used_by[new_prod].add(self.name)

    @staticmethod
    def load(grammar: "Grammar", name: str, *rules: Iterable[str]) -> "Production":
        return Production(
            grammar,
            name,
            *(Rule.load(grammar, *alternatives) for alternatives in rules),
        )

    def add(self, rule: Rule) -> bool:
        # check if the rule already exists
        if rule in self.rules:
            return False
        self.rules.add(rule)
        for term in rule.sequence:
            if isinstance(term, NonTerminal):
                self.grammar.used_by[term].add(self.name)
        # TODO: investigate checking for common subsequences and generating new sub-productions for those
        return True

    def __contains__(self, rule: Rule):
        return rule in self.rules

    def __iter__(self) -> Iterator[Rule]:
        return iter(self.rules)

    def __len__(self):
        return len(self.rules)

    def __eq__(self, other):
        return isinstance(other, Production) and self.rules == other.rules

    def __hash__(self):
        return hash(frozenset(self.rules))

    def __str__(self):
        rules = " | ".join(map(str, self.rules))
        if self.grammar.start is self:
            start = "--> "
        else:
            start = ""
        return f"{start}{self.name} ::= {rules}"


class GrammarError(RuntimeError):
    pass


class DisconnectedGrammarError(GrammarError):
    pass


class CorruptedGrammarError(GrammarError):
    pass


class MissingProductionError(CorruptedGrammarError):
    pass


ParseTreeValue = Union[Production, Rule, Terminal]


class PartialMatch:
    __slots__ = "tree", "remaining_symbols", "remaining_bytes"

    def __init__(self, tree: ParseTree[ParseTreeValue], remaining_symbols: Tuple[Symbol, ...], remaining_bytes: bytes):
        self.tree: ParseTree[ParseTreeValue] = tree
        self.remaining_symbols: Tuple[Symbol, ...] = remaining_symbols
        self.remaining_bytes: bytes = remaining_bytes


class EarleyState(metaclass=ABCMeta):
    __slots__ = "prediction", "parsed", "expected", "index", "depth", "predecessors"

    def __init__(self, prediction: "Prediction", parsed: Tuple[Symbol, ...], expected: Tuple[Symbol, ...], index: int):
        self.prediction: Prediction = prediction
        self.parsed: Tuple[Symbol, ...] = parsed
        self.expected: Tuple[Symbol, ...] = expected
        self.index: int = index
        self.depth: int = 0
        self.predecessors: FrozenSet[EarleyState] = frozenset()

    @property
    def production(self) -> Production:
        return self.prediction.production

    def add_predecessor(self, left_sibling: "EarleyState"):
        assert left_sibling.prediction == self.prediction
        self.predecessors = self.predecessors | {left_sibling}
        self.depth = min(p.depth for p in self.predecessors) + 1

    @property
    def finished(self) -> bool:
        return len(self.expected) == 0

    @property
    def next_element(self) -> Symbol:
        return self.expected[0]

    @abstractmethod
    def to_tree(self) -> MutableParseTree[ParseTreeValue]:
        raise NotImplementedError()

    def __hash__(self):
        return hash((self.parsed, self.expected, self.index, self.prediction))

    def __eq__(self, other):
        return self.__class__ == other.__class__ and (
            self.index == other.index
            and self.parsed == other.parsed
            and self.expected == other.expected
            and self.prediction == other.prediction
        )

    def __str__(self):
        parsed = "".join(map(str, self.parsed))
        expected = "".join(map(repr, self.expected))
        return f"({self.production.name} → {parsed}•{expected}, {self.index})"


class Prediction(EarleyState):
    __slots__ = "_production", "rule"

    def __init__(
        self, production: Production, parsed: Tuple[Symbol, ...], expected: Tuple[Symbol, ...], index: int, rule: Rule
    ):
        super().__init__(self, parsed, expected, index)
        self._production: Production = production
        self.rule: Rule = rule

    @property
    def production(self) -> Production:
        return self._production

    def to_tree(self) -> MutableParseTree[ParseTreeValue]:
        return MutableParseTree(self.rule)

    def __hash__(self):
        return hash((self.parsed, self.expected, self.index, self.production))

    def __eq__(self, other):
        if isinstance(other, Prediction):
            return (
                self.index == other.index
                and self.parsed == other.parsed
                and self.expected == other.expected
                and self.production == other.production
            )
        else:
            return False

    def __ne__(self, other):
        return not (self == other)


class EmptyProduction(EarleyState):
    __slots__ = "_production"

    def __init__(
        self,
        production: Production,
        prediction: Prediction,
        parsed: Tuple[Symbol, ...],
        expected: Tuple[Symbol, ...],
        index: int,
    ):
        super().__init__(prediction, parsed, expected, index)
        self._production: Production = production

    __hash__ = EarleyState.__hash__  # type: ignore

    __ne__ = EarleyState.__ne__  # type: ignore

    def __eq__(self, other):
        return isinstance(other, EmptyProduction) and EarleyState.__eq__(self, other) and self._production == other._production

    def to_tree(self) -> MutableParseTree[ParseTreeValue]:
        return MutableParseTree(self._production)


class Completion(EarleyState):
    __slots__ = "completed_by"

    def __init__(self, prediction: Prediction, parsed: Tuple[Symbol, ...], expected: Tuple[Symbol, ...], index: int):
        super().__init__(prediction=prediction, parsed=parsed, expected=expected, index=index)
        self.completed_by: Set[EarleyState] = set()

    __hash__ = EarleyState.__hash__  # type: ignore

    __eq__ = EarleyState.__eq__  # type: ignore

    __ne__ = EarleyState.__ne__  # type: ignore

    def to_tree(self) -> MutableParseTree[ParseTreeValue]:
        return MutableParseTree(self.production)


class ScannedTerminal(EarleyState):
    __slots__ = "terminal"

    def __init__(
        self, prediction: Prediction, parsed: Tuple[Symbol, ...], expected: Tuple[Symbol, ...], index: int, terminal: Terminal
    ):
        super().__init__(prediction, parsed, expected, index)
        self.terminal: Terminal = terminal

    def __hash__(self):
        return hash((super().__hash__(), self.terminal))

    def __eq__(self, other):
        return isinstance(other, ScannedTerminal) and other.terminal == self.terminal and EarleyState.__eq__(self, other)

    __ne__ = EarleyState.__ne__  # type: ignore

    def to_tree(self) -> MutableParseTree[ParseTreeValue]:
        return MutableParseTree(self.terminal)


S = TypeVar("S", bound=EarleyState)


class EarleyQueue:
    def __init__(self, parser: "EarleyParser"):
        self.parser: EarleyParser = parser
        self.queue: List[EarleyState] = []
        self.elements: Dict[EarleyState, EarleyState] = {}
        self.waiting_for: Dict[NonTerminal, Set[EarleyState]] = defaultdict(set)
        self.already_completed: Dict[NonTerminal, Dict[EarleyState, Set[int]]] = defaultdict(lambda: defaultdict(set))

    def complete_state(self, state: EarleyState, completed: EarleyState):
        assert not state.finished
        assert isinstance(state.next_element, NonTerminal)
        assert state.next_element == completed.production.name
        new_state = Completion(
            prediction=state.prediction, parsed=state.parsed + completed.parsed, expected=state.expected[1:], index=state.index
        )
        self.add(new_state, left_sibling=state).completed_by.add(completed)

    def add(self, state: S, left_sibling: Optional[EarleyState] = None) -> S:
        if state in self.elements:
            # We already have this state
            state = cast(S, self.elements[state])
        else:
            self.queue.append(state)
            self.elements[state] = state
        if not state.finished and isinstance(state.next_element, NonTerminal):
            self.waiting_for[state.next_element].add(state)
            for completed, k_set in self.already_completed[state.next_element].items():
                for k in k_set:
                    self.parser.states[k].complete_state(state, completed)
        if left_sibling is not None:
            state.add_predecessor(left_sibling)
        return state

    def remove(self, *states: Union[EarleyState, Iterable]) -> int:
        num_removed: int = 0
        state_set = set()
        for state in states:
            if isinstance(state, set):
                state_set |= state
            elif isinstance(state, EarleyState):
                state_set.add(state)
            else:
                state_set |= set(state)
        size_before: int = len(self.elements)
        self.queue = [e for e in self.queue if e not in state_set]
        self.elements = {e: e for e in self.queue}
        for s in self.waiting_for.values():
            s -= state_set
        for e in self.queue:
            e.predecessors = e.predecessors - state_set
        num_removed += size_before - len(self.elements)
        return num_removed

    def __contains__(self, item):
        return item in self.elements

    def __getitem__(self, state: EarleyState) -> EarleyState:
        return self.elements[state]

    def __len__(self):
        return len(self.elements)

    def __iter__(self) -> Iterator[EarleyState]:
        # allow the EarleyQueue to be modified during iteration
        i = 0
        while len(self.queue) > i:
            yield self.queue[i]
            i += 1


class EarleyParser:
    def __init__(self, grammar: "Grammar", sentence: Union[str, bytes], start: Optional[Production] = None):
        self.grammar: Grammar = grammar
        if isinstance(sentence, str):
            self.sentence: bytes = sentence.encode("utf-8")
        else:
            self.sentence = sentence
        if start is None:
            if self.grammar.start is None:
                raise ValueError("Either the grammar must have a start production or one must be provided")
            self.start: Production = self.grammar.start
        else:
            self.start = start
        self.states: List[EarleyQueue] = [EarleyQueue(self) for _ in range(len(sentence) + 1)]
        self.parsed: bool = False
        self.start_states: FrozenSet[Prediction] = frozenset()

    @property
    def end_states(self) -> Iterator[EarleyState]:
        return (s for s in self.states[-1] if s.finished and s.production == self.start)

    def parse(self) -> Iterator[ParseTree[ParseTreeValue]]:
        if not self.parsed:
            self.parsed = True
            self.start_states = frozenset(
                [
                    Prediction(production=self.start, parsed=(), expected=rule.sequence, index=0, rule=rule)
                    for rule in self.start.rules
                ]
            )
            for start_state in self.start_states:
                self.states[0].add(start_state)
            last_k_with_match = -1
            for k in trange(len(self.sentence) + 1, leave=False, desc="Parsing", unit=" bytes"):
                for state in self.states[k]:
                    if not state.finished:
                        next_element = state.next_element
                        if isinstance(next_element, NonTerminal):
                            # print(f"{type(state)}: {state}")
                            # do not predict off of a non-initial Prediction
                            if not isinstance(state, Prediction) or not state.parsed:
                                # state is either a Completion, a Scanned Terminal, or a Prediction that has nothing
                                # parsed yet
                                self._predict(state, k)
                        else:
                            if self._scan(state, k):
                                last_k_with_match = max(last_k_with_match, k + len(state.next_element.terminal) - 1)
                    else:
                        self._complete(state, k)
            if last_k_with_match < len(self.sentence) - 1:
                offset = last_k_with_match + 1
                raise ValueError(
                    f"Unexpected byte {self.sentence[offset:offset+1]!r} at offset "
                    f"{last_k_with_match+1}\n{highlight_offset(self.sentence, offset)}"
                )
        return self.parse_trees()

    def parse_trees(self) -> Iterator[ParseTree[ParseTreeValue]]:
        """Reconstructs all parse trees from the parse"""
        if not self.parsed:
            yield from self.parse()
            return

        for end_state in self.end_states:
            root = _Node(end_state)
            while True:
                tree = MutableParseTree(self.start)
                tree.children = [n.tree.clone() for n in root.siblings]
                yield tree  # type: ignore
                if not root.iterate():
                    break

    def _predict(self, state: EarleyState, k: int):
        prod: Production = self.grammar[state.next_element]  # type: ignore
        if not prod.can_produce_terminal:
            new_state: EarleyState = EmptyProduction(
                prediction=state.prediction, production=prod, parsed=(), expected=(), index=k
            )
            self.states[k].add(new_state)
            return
        for rule in prod.rules:
            new_state = Prediction(production=prod, parsed=(), expected=rule.sequence, index=k, rule=rule)
            self.states[k].add(new_state)

    def _scan(self, state: EarleyState, k: int) -> bool:
        expected_element = state.next_element
        terminal = expected_element.terminal  # type: ignore
        if not self.sentence[k:].startswith(terminal):
            return False
        new_state = ScannedTerminal(
            prediction=state.prediction,
            parsed=state.parsed + (state.next_element,),
            expected=state.expected[1:],
            index=state.index,
            terminal=expected_element,  # type: ignore
        )
        self.states[k + len(terminal)].add(new_state, left_sibling=state)
        return True

    def _complete(self, completed: EarleyState, k: int):
        self.states[completed.index].already_completed[completed.production.name][completed].add(k)
        for state in self.states[completed.index].waiting_for[completed.production.name]:
            self.states[k].complete_state(state, completed)


class _Node:
    def __init__(self, state: EarleyState, parent: Optional["_Node"] = None, _initialize: bool = True):
        self.parent: Optional[_Node] = parent
        if parent is None:
            self.root: _Node = self
            self.history: Set[EarleyState] = {state}
        else:
            self.root = parent.root
            self.history = parent.history
            self.history.add(state)
        self.state: EarleyState = state
        self.sibling_possibilities: Iterator[EarleyState] = iter(sorted(state.predecessors, key=lambda p: p.depth))
        if isinstance(state, Completion):
            self.child_possibilities: Iterator[EarleyState] = iter(sorted(state.completed_by, key=lambda p: p.depth))
        else:
            self.child_possibilities = iter(())
        self.rightmost_child: Optional[_Node] = None
        self.left_sibling: Optional[_Node] = None
        if isinstance(self.state, Prediction) and parent is not None:
            self.tree: MutableParseTree[ParseTreeValue] = MutableParseTree(self.state.rule)
        elif isinstance(self.state, ScannedTerminal):
            self.tree = MutableParseTree(self.state.terminal)
        else:
            self.tree = MutableParseTree(self.state.production)

        if _initialize:
            stack: List[_Node] = [self]
            while stack:
                node = stack.pop()
                try:
                    left_sibling = node.next_sibling()
                    node.left_sibling = _Node(left_sibling, parent=self.parent, _initialize=False)
                    stack.append(node.left_sibling)
                except StopIteration:
                    pass
                try:
                    rightmost_child = node.next_child()
                    node.rightmost_child = _Node(rightmost_child, parent=self, _initialize=False)
                    stack.append(node.rightmost_child)
                except StopIteration:
                    pass
            for node in self.postorder_traversal():
                if node.rightmost_child is not None:
                    node.tree.children = [child.tree for child in node.rightmost_child.siblings]
            if parent is not None:
                parent.tree.children = [child.tree for child in parent.children]

    def next_sibling(self) -> EarleyState:
        while True:
            left_sibling = next(self.sibling_possibilities)
            if left_sibling not in self.history:
                return left_sibling

    def next_child(self) -> EarleyState:
        while True:
            rightmost_child = next(self.child_possibilities)
            if rightmost_child not in self.history:
                return rightmost_child

    def descendants(self) -> Iterator[EarleyState]:
        stack: List[_Node] = [self]
        while stack:
            node = stack.pop()
            yield node.state
            if node.left_sibling:
                stack.append(node.left_sibling)
            if node.rightmost_child:
                stack.append(node.rightmost_child)

    @property
    def siblings(self) -> Iterator["_Node"]:
        nodes = [self]
        while nodes[-1].left_sibling is not None:
            nodes.append(nodes[-1].left_sibling)
        return reversed(nodes)

    @property
    def children(self) -> Iterator["_Node"]:
        if self.rightmost_child is not None:
            yield from self.rightmost_child.siblings

    def _iterate_local(self) -> bool:
        try:
            left_sibling = self.next_sibling()
            if self.left_sibling is not None:
                self.history -= set(self.left_sibling.descendants())
            self.left_sibling = _Node(left_sibling, parent=self.parent)
            return True
        except StopIteration:
            pass
        try:
            rightmost_child = self.next_child()
            if self.rightmost_child is not None:
                self.history -= set(self.rightmost_child.descendants())
            self.rightmost_child = _Node(rightmost_child, parent=self)
            return True
        except StopIteration:
            return False

    def postorder_traversal(self) -> Iterator["_Node"]:
        stack: List[Tuple[bool, _Node]] = [(False, self)]

        while stack:
            expanded, node = stack.pop()
            if not expanded:
                stack.append((True, node))
                if node.left_sibling is not None:
                    stack.append((False, node.left_sibling))
                if node.rightmost_child is not None:
                    stack.append((False, node.rightmost_child))
            else:
                yield node

    def iterate(self) -> bool:
        for node in self.postorder_traversal():
            if node._iterate_local():
                return True
        return False


class Match:
    def __init__(self, parser: EarleyParser):
        self.parser: EarleyParser = parser
        self._is_match: Optional[bool] = None

    @property
    def parse_tree(self) -> Optional[ParseTree[ParseTreeValue]]:
        """Returns the first parse tree matched"""
        if self._is_match is None:
            try:
                tree = next(iter(self.parser.parse()))
                self._is_match = True
                return tree
            except StopIteration:
                self._is_match = False
        elif self._is_match:
            return next(iter(self.parser.parse_trees()))
        return None

    def __bool__(self):
        if self._is_match is None:
            return self.parse_tree is not None
        else:
            return self._is_match

    def __iter__(self) -> Iterator[ParseTree[ParseTreeValue]]:
        return self.parser.parse_trees()


class Grammar:
    def __init__(self):
        self.productions: Dict[NonTerminal, Production] = {}
        self.used_by: Dict[NonTerminal, Set[NonTerminal]] = defaultdict(set)
        self.start: Optional[Production] = None

    def match(self, sentence: Union[str, bytes], start: Optional[Production] = None) -> Match:
        parser = EarleyParser(grammar=self, sentence=sentence, start=start)
        return Match(parser)

    def find_partial_trees(self, sentence: bytes, start: Optional[Production] = None) -> Iterator[ParseTree[ParseTreeValue]]:
        """Enumerates all partial parse trees that could result in the given starting sentence fragment."""
        if start is None:
            start = self.start
        for pm in start.partial_match(sentence):  # type: ignore
            yield pm.tree

    def dependency_graph(self) -> DiGraph[Production]:
        graph: DiGraph[Production] = DiGraph()
        for prod in self.productions:
            graph.add_node(prod)
        for prod_name, used_by_names in self.used_by.items():
            if prod_name not in self:
                Production(self, prod_name)
            for used_by_name in used_by_names:
                if used_by_name not in self:
                    Production(self, used_by_name)
                graph.add_edge(self[used_by_name], self[prod_name])
        return graph

    def load(self, raw_grammar: Dict[str, Any]):
        for name, definition in raw_grammar.items():
            Production.load(self, name, *definition)

    def remove(self, production: Union[NonTerminal, Production]) -> bool:
        if isinstance(production, Production):
            name: str = production.name
            if name not in self:
                return False
        else:
            name = production
            if name not in self:
                return False
            production = self[name]
        # update all of the productions we use
        for rule in production:
            for v in rule.sequence:  # type: ignore   # mypy is dumb and thinks that this can sometimes be a str?
                if isinstance(v, NonTerminal):
                    try:
                        self.used_by[v].remove(name)
                    except KeyError:
                        pass
        # update all of the productions that use us
        for uses_name in list(self.used_by[name]):
            if uses_name != name:
                self[uses_name].remove_sub_production(name)
        del self.used_by[name]
        del self.productions[name]
        return True

    def verify(self, test_disconnection: bool = True):
        for prod in self.productions.values():
            for rule in prod:
                for v in rule.sequence:
                    if isinstance(v, str):
                        if v not in self:
                            raise MissingProductionError(f"Production {prod.name} references {v}, which is not in the grammar")
                        elif prod.name not in self.used_by[v]:
                            raise CorruptedGrammarError(
                                f"Production {prod.name} references {v} but that is not "
                                'recorded in the "used by" table: '
                                f"{self.used_by[prod.name]!r}"
                            )
            for user in self.used_by[prod.name]:
                if user not in self:
                    raise CorruptedGrammarError(
                        f"Production {prod.name} is used by {user}, but {user} production is not in the grammar"
                    )
            # if not self.used_by[prod.name] and self.start is not prod:
            #     print(f"Warning: Production {prod.name} is never used")
        for prod_name in self.used_by.keys():
            if prod_name not in self:
                raise CorruptedGrammarError(f'Production {prod_name} is in the "used by" table, but not in the grammar')
        if self.start is not None and test_disconnection:
            # make sure there is a path from start to every other production
            graph = self.dependency_graph()
            visited = set(node for node in nx.dfs_preorder_nodes(graph, source=self.start))
            if len(visited) < len(self.productions):
                not_visited_prods = set(node for node in self.productions.values() if node not in visited)
                # it's okay if the unvisited productions aren't able to produce terminals
                not_visited = [node.name for node in not_visited_prods if node.can_produce_terminal]
                if not_visited:
                    raise DisconnectedGrammarError(
                        "These productions are not accessible from the start production "
                        f"{self.start.name}: {', '.join(not_visited)}"
                    )

    def simplify(self) -> bool:
        modified = False
        with tqdm(desc="garbage collecting", unit=" productions", leave=False, unit_divisor=1) as status:
            for prod in tqdm(
                list(self.productions.values()),
                desc="simplifying trivial productions",
                unit=" productions",
                leave=False,
                unit_divisor=1,
            ):
                # remove any rules in the production that just recursively call the same production
                prod.remove_recursive_rules()
                if prod.removable and len(prod.rules) == 1:
                    # this production has a single rule, so replace all uses with that rule
                    for user in list(prod.used_by):
                        user.replace_sub_production(prod.name, prod.first_rule())  # type: ignore
                    self.remove(prod)
                    modified = True
                    # print(f"replaced {prod} with {prod.first_rule()}")
                    # self.verify(test_disconnection=False)
                    status.update(1)
            for prod in tqdm(
                list(self.productions.values()),
                desc="removing empty productions",
                unit=" productions",
                leave=False,
                unit_divisor=1,
            ):
                if prod.removable and not prod.can_produce_terminal:
                    removed = self.remove(prod)
                    assert removed
                    # print(f"removed {prod} because it was empty")
                    # self.verify(test_disconnection=False)
                    status.update(1)
                    modified = True
        return modified
        modified = False
        modified_last_pass = True
        with tqdm(desc="garbage collecting", unit=" productions", leave=False, unit_divisor=1) as status:
            while modified_last_pass:
                modified_last_pass = False
                for prod in list(self.productions.values()):
                    # remove any rules in the production that just recursively call the same production
                    recursive_rules = prod.remove_recursive_rules()
                    modified_last_pass = bool(recursive_rules)
                    if not prod.can_produce_terminal and prod is not self.start:
                        # remove any produtions that only produce empty strings
                        removed = self.remove(prod)
                        assert removed
                        # print(f"removed {prod} because it was empty")
                        # self.verify(test_disconnection=False)
                        status.update(1)
                        modified_last_pass = True
                    elif len(prod.rules) == 1 and prod is not self.start:
                        # this production has a single rule, so replace all uses with that rule
                        for user in list(prod.used_by):
                            user.replace_sub_production(prod.name, prod.first_rule())  # type: ignore
                        self.remove(prod)
                        # print(f"replaced {prod} with {prod.first_rule()}")
                        # self.verify(test_disconnection=False)
                        status.update(1)
                        modified_last_pass = True
                modified = modified or modified_last_pass
            # traverse the productions from the least dominant up
            dominators = self.dependency_graph().dominator_forest
            ordered_productions: List[Production] = list(nx.dfs_postorder_nodes(dominators, source=self.start))
            # see if any of the productions are equivalent. if so, combine them
            for p1, p2 in itertools.combinations(ordered_productions, 2):
                if p1 == p2:
                    # p2 dominates p1 in the grammar, so replace p1 with p2
                    for user in list(p1.used_by):
                        user.replace_sub_production(p1.name, p2.name)  # type: ignore
                    self.remove(p1)
                    status.update(1)
                    modified = True

            return modified

    def __len__(self):
        return len(self.productions)

    def __iter__(self) -> Iterator[Production]:
        yield from self.productions.values()

    def __getitem__(self, prod_name: str) -> Production:
        return self.productions[prod_name]

    def __contains__(self, prod_name: str):
        return prod_name in self.productions

    def __str__(self):
        return "\n".join(map(str, self.productions.values()))


def production_name(event: TraceEvent) -> str:
    if isinstance(event, BasicBlockEntry):
        return f"<{event!s}>"
    else:
        return f"<{event.function.name}>"


def parse_tree_to_grammar(tree: NonGeneralizedParseTree) -> Grammar:
    grammar = Grammar()

    for node in tree.preorder_traversal():
        if isinstance(node.value, Terminal):
            continue
        sequence: List[Union[Terminal, str]] = []
        for child in node.children:
            if isinstance(child.value, Terminal):
                sequence.append(child.value)
            else:
                sequence.append(production_name(child.value))

        rule = Rule(grammar, *sequence)
        if isinstance(node.value, Start):
            prod_name = "<START>"
        else:
            prod_name = production_name(node.value)
        if prod_name in grammar:
            production = grammar[prod_name]
            if rule not in production:
                production.add(rule)
        else:
            prod = Production(grammar, prod_name, rule)
            if prod_name == "<START>":  # or isinstance(node.value, FunctionCall):
                # TODO: Re-implement the `or isinstance...` above
                # do not allow the START production or function calls to be simplified out of the grammar
                prod.removable = False

    grammar.start = grammar["<START>"]

    return grammar


def trace_to_grammar(trace: ProgramTrace) -> Grammar:
    # trace.simplify()

    grammar = Grammar()

    entrypoint = trace.entrypoint
    if entrypoint is None:
        grammar.start = Production(grammar, "<START>")
        return grammar
    func_stack: List[FunctionInvocation] = [entrypoint]

    num_funcs = trace.num_function_calls()

    with tqdm(unit=" productions", leave=False, desc="extracting a base grammar", total=num_funcs) as t:
        while func_stack:
            func = func_stack.pop()
            t.update(1)
            prod_name = production_name(func)

            if grammar.start is None and func is entrypoint:
                grammar.start = Production(grammar, "<START>", Rule.load(grammar, prod_name))

            if not func.touched_taint:
                # do not expand the function if it didn't touch taint
                _ = Production(grammar, prod_name)
                t.write(f"skipping {func.function.demangled_name} because it didn't touch taint")
                t.update(sum(1 for _ in func.calls()))
                continue
            elif func.function_entry.entrypoint is None:
                _ = Production(grammar, prod_name)
            else:
                rule = Rule(grammar, production_name(func.function_entry.entrypoint))
                if prod_name in grammar:
                    production = grammar[prod_name]
                    if rule not in production:
                        production.add(rule)
                else:
                    _ = Production(grammar, prod_name, rule)

                bbs: List[Optional[BasicBlockEntry]] = list(func.basic_blocks())
                for bb, next_bb in tqdm(
                    zip(bbs, bbs[1:] + [None]),
                    leave=False,
                    unit=" basic blocks",
                    desc=func.function.demangled_name,
                    delay=1.0,
                    total=len(bbs),
                ):
                    sub_productions: List[Union[Terminal, str]] = [Terminal(token) for token in bb.consumed_tokens]

                    called_function = bb.called_function

                    if called_function is not None:
                        func_stack.append(called_function)
                        sub_productions.append(production_name(called_function))
                        ret = called_function.function_return
                        if ret is not None:
                            returning_to = ret.returning_to
                            if returning_to is not None:
                                sub_productions.append(f"<{returning_to!s}>")
                            else:
                                # TODO: Print warning
                                pass
                                # breakpoint()
                        else:
                            # TODO: Print warning
                            pass
                            # breakpoint()

                    if next_bb is not None:
                        rules = [Rule(grammar, *(sub_productions + [f"<{next_bb!s}>"]))]
                    else:
                        rules = [Rule(grammar, *sub_productions)]

                    bb_prod_name = production_name(bb)

                    if bb_prod_name in grammar:
                        production = grammar[bb_prod_name]
                        for rule in rules:
                            if rule not in production:
                                production.add(rule)
                    else:
                        Production(grammar, bb_prod_name, *rules)

    grammar.verify()

    return grammar


@PolyTrackerREPL.register("extract_grammar")
def extract(traces: Iterable[ProgramTrace], simplify: bool = False) -> Grammar:
    """extract a grammar from a set of traces"""
    trace_iter: Iterable[ProgramTrace] = tqdm(traces, unit=" trace", desc="extracting traces", leave=False)
    for trace in trace_iter:
        inputs = list(trace.inputs)
        if len(inputs) == 0:
            raise ValueError(f"Trace {trace} did not load any taints")
        source = inputs[0]
        if len(inputs) > 1:
            log.warning(f"Trace {trace} operated on multiple inputs; using {source}")
        properties = trace.input_properties(source)
        if properties.unused_byte_offsets:
            log.warning(
                "Warning: The following byte offsets were never recorded as being read in the trace: "
                f"        {[(offset, source.content[offset:offset+1]) for offset in properties.unused_byte_offsets]!r}"
            )
        if properties.out_of_order_byte_offsets:
            log.warning(
                "Warning: The trace read the following bytes out of order (implying that the trace is of a parser that "
                f"is not a pure recursive descent parser): {', '.join(map(str, properties.out_of_order_byte_offsets))}"
            )
        if properties.file_seeks:
            # this should only ever happen if properties.out_of_order_byte_offsets is also populated
            seeks = [f"⎆{i}:⎗{from_offset}→{to_offset}⎘" for i, from_offset, to_offset in properties.file_seeks]
            log.info(f"The parser backtracked from one offset to another at the following event indexes: {', '.join(seeks)}")
        tree = trace_to_non_generalized_tree(trace)
        match_before = tree.matches()
        tree.simplify()
        assert match_before == tree.matches() == source.content
        # TODO: Merge the grammars
        grammar = parse_tree_to_grammar(tree)
        if simplify:
            grammar.simplify()
        return grammar
    return Grammar()


def to_dot(graph: DiGraph, comment: Optional[str] = None) -> graphviz.Digraph:
    """
    :param comment: comment for the graph
    :return: Graphviz DiGraph

    This function creates a dot object which can be saved to disk and converted to PDF
    its a visualization of the chain fragment, useful for visualizing a reorg.
    """
    if comment is not None:
        dot = graphviz.Digraph(comment=comment)
    else:
        dot = graphviz.Digraph()
    for node in graph.nodes:
        dot.node(f"{str(node)}")
    for parent in graph.graph.keys():
        for child in graph.graph[parent]:
            dot.edge(f"{str(parent)}", f"{str(child)}")
    return dot


class ExtractGrammarCommand(Command):
    name = "grammar"
    help = "extract a grammar from one or more program traces"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.traces: List[ProgramTrace] = []
        self.grammar: Optional[Grammar] = None

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument(
            "TRACES",
            nargs="+",
            type=str,
            help="extract a grammar from the provided PolyTracker trace databases",
        )
        parser.add_argument("--simplify", "-s", action="store_true", help="simplify the grammar")

    def run(self, args: Namespace):
        self.traces = []
        try:
            for trace_db_path in args.TRACES:
                trace = PolyTrackerTrace.load(trace_db_path)
                # to_dot(trace.cfg).save("cfg.dot")
                # print(f"num nodes {trace.cfg.number_of_nodes()}")
                # if not trace.is_cfg_connected():
                #     roots = list(trace.cfg_roots())
                #     if len(roots) == 0:
                #         log.error(f"Basic block trace of {trace_db_path} has no roots!\n\n")
                #     else:
                #         root_names = "".join(f"\t{r!s}\n" for r in roots)
                #         log.error(
                #             f"Basic block trace of {trace_db_path} has multiple roots:\n{root_names}"
                #         )
                #     exit(1)
                self.traces.append(trace)
        except ValueError as e:
            log.error(f"{e!s}\n\n")
            exit(1)
        self.grammar = extract(self.traces, args.simplify)
        print(str(self.grammar))
