import itertools
from collections import defaultdict
from typing import Any, Dict, FrozenSet, Iterable, Iterator, List, Optional, Set, Tuple, Union

import networkx as nx
from tqdm import tqdm, trange

from .cfg import DiGraph
from .parsing import highlight_offset, ImmutableParseTree, MutableParseTree, NonGeneralizedParseTree, ParseTree, \
    Start, Terminal, trace_to_non_generalized_tree
from .tracing import BasicBlockEntry, FunctionCall, FunctionReturn, PolyTrackerTrace, TraceEvent


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
                                    remaining_bytes[len(next_symbol.terminal) :],
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
                prod for prod in self.grammar.productions.values()
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
        return Production(grammar, name, *(Rule.load(grammar, *alternatives) for alternatives in rules))

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


class EarleyState:
    __slots__ = "production", "parsed", "expected", "index", "rule_or_terminal", "predecessors", "completed_by", \
                "successors"

    def __init__(
        self,
        production: Production,
        parsed: Tuple[Symbol, ...],
        expected: Tuple[Symbol, ...],
        index: int,
        rule_or_terminal: Optional[Union[Rule, Terminal]] = None,
    ):
        self.production: Production = production
        self.parsed: Tuple[Symbol, ...] = parsed
        self.expected: Tuple[Symbol, ...] = expected
        self.index: int = index
        self.rule_or_terminal: Optional[Union[Rule, Terminal]] = rule_or_terminal
        self.predecessors: Set[EarleyState] = set()
        self.completed_by: Set[EarleyState] = set()
        self.successors: Set[EarleyState] = set()  # This is populated during pruning

    @property
    def finished(self) -> bool:
        return len(self.expected) == 0

    @property
    def next_element(self) -> Symbol:
        return self.expected[0]

    def __hash__(self):
        return hash((self.parsed, self.expected, self.index, self.production))

    def __eq__(self, other):
        if isinstance(other, EarleyState):
            return (
                self.index == other.index
                and self.parsed == other.parsed
                and self.expected == other.expected
                and self.production == other.production
            )
        else:
            return False

    def __str__(self):
        parsed = "".join(map(str, self.parsed))
        expected = "".join(map(repr, self.expected))
        return f"({self.production.name} → {parsed}•{expected}, {self.index})"


class EarleyQueue:
    def __init__(self):
        self.queue: List[EarleyState] = []
        self.elements: Dict[EarleyState, EarleyState] = {}
        self.waiting_for: Dict[NonTerminal, Set[EarleyState]] = defaultdict(set)

    def add(self, state: EarleyState, left_sibling: Optional[EarleyState] = None) -> bool:
        if state in self.elements:
            # We already have this state
            if left_sibling is not None:
                self.elements[state].predecessors.add(left_sibling)
            return False
        self.queue.append(state)
        self.elements[state] = state
        if not state.finished and isinstance(state.next_element, NonTerminal):
            self.waiting_for[state.next_element].add(state)
        if left_sibling is not None:
            state.predecessors.add(left_sibling)
        return True

    def remove(self, *states: Union[EarleyState, Iterable]) -> int:
        num_removed: int = 0
        for state in states:
            if isinstance(state, EarleyState):
                return self.remove({state})
            elif not isinstance(state, set):
                return self.remove(set(state))
            size_before: int = len(self.elements)
            self.queue = [e for e in self.queue if e not in state]
            self.elements = {e: e for e in self.queue}
            for s in self.waiting_for.values():
                s -= state
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
        self.states: List[EarleyQueue] = [EarleyQueue() for _ in range(len(sentence) + 1)]
        self.parsed: bool = False
        self.start_states: List[EarleyState] = []

    def _prune(self) -> int:
        """Removes Earley states that cannot lead to a match

        Also sets each state's successors set
        """
        if not self.parsed:
            self.parse()
        with tqdm(desc="garbage collecting Earley states", unit=" states", leave=False, total=1) as t:
            is_valid: Set[EarleyState] = {state for queue in self.states for state in queue if state.finished}
            to_visit = list(is_valid)
            while to_visit:
                state = to_visit.pop()
                predecessors = [p for p in state.predecessors if p not in is_valid]
                for p in predecessors:
                    p.successors.add(state)
                to_visit.extend(predecessors)
                is_valid |= set(predecessors)
                t.total = len(to_visit) + len(is_valid)
                t.update(1)
        removed: int = 0
        with tqdm(desc="pruning unused Earley states", unit=" states", leave=False, initial=0) as t:
            for queue in tqdm(self.states, desc="processing", unit=" queues", leave=False):
                removed += queue.remove(*(queue.elements.keys() - is_valid))
                t.update(removed)
        return removed

    def parse(self) -> Iterator[ParseTree[ParseTreeValue]]:
        if not self.parsed:
            self.parsed = True
            self.start_states = [
                EarleyState(production=self.start, parsed=(), expected=rule.sequence, index=0)
                for rule in self.start.rules
            ]
            for start_state in self.start_states:
                self.states[0].add(start_state)
            last_k_with_match = -1
            for k in trange(len(self.sentence) + 1, leave=False, desc="Parsing", unit=" bytes"):
                for state in self.states[k]:
                    if not state.finished:
                        next_element = state.next_element
                        if isinstance(next_element, NonTerminal):
                            # print(state)
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
            self._prune()
        return self.parse_trees()

    def parse_trees(self) -> Iterator[ParseTree[ParseTreeValue]]:
        """Reconstructs all parse trees from the parse"""
        if not self.parsed:
            return self.parse()

        class NodeState:
            def __init__(self, state: EarleyState, parent: Optional["NodeState"] = None):
                self.state: EarleyState = state
                self._successors_iter: Iterator[EarleyState] = iter(state.successors)
                self._completed_by_iter: Iterator[EarleyState] = iter(state.completed_by)
                try:
                    self.successors: Optional[EarleyState] = next(self._successors_iter)
                except StopIteration:
                    self._successor = None
                try:
                    self._completed_by: Optional[EarleyState] = next(self._completed_by_iter)
                except StopIteration:
                    self._completed_by = None
                self.parent: NodeState = parent
                self._successor_node: Optional[NodeState] = None
                self._completed_by_node: Optional[NodeState] = None

            @property
            def successor(self) -> Optional["NodeState"]:
                if self._successor_node is None and self._successor is not None:
                    self._successor_node = NodeState(self._successor)
                return self._successor_node

            @property
            def completed_by(self) -> Optional["NodeState"]:
                if self._completed_by_node is None and self._completed_by is not None:
                    self._completed_by_node = NodeState(self._completed_by)
                return self._completed_by_node

            def postorder(self) -> Iterator["NodeState"]:
                stack: List[Tuple[bool, NodeState]] = [(False, self)]
                while stack:
                    expanded, node = stack.pop()
                    if not expanded and (node._successor is not None or node._completed_by is not None):
                        stack.append((True, node))
                        if node._successor is not None:
                            stack.append((False, node.successor))
                        if node._completed_by is not None:
                            stack.append((False, node.completed_by))
                    else:
                        yield node

            def iterate(self) -> bool:
                i: Iterator[NodeState] = self.postorder()
                for node in i:
                    if node._successor is not None:
                        try:
                            self._successor = next(self._successors_iter)
                            self._successor_node = None
                            return True
                        except StopIteration:
                            pass
                    if self._completed_by is not None:
                        try:
                            self._completed_by = next(self._completed_by_iter)
                            self._completed_by_node = None
                            return True
                        except StopIteration:
                            pass
                    return False

            def siblings(self) -> Iterator["NodeState"]:
                node: Optional[NodeState] = self
                while node is not None:
                    yield node
                    if not node.state.finished:
                        break
                    node = node.successor

            def tree(self) -> MutableParseTree[ParseTreeValue]:
                root: Optional[MutableParseTree[ParseTreeValue]] = None
                to_expand: List[
                    Tuple[NodeState, Optional[MutableParseTree[ParseTreeValue]]]
                ] = [(self, None)]
                while to_expand:
                    node, parent = to_expand.pop()
                    if node.completed_by is not None:
                        assert node.is_non_terminal()
                        tree = MutableParseTree(node.state.production)
                        to_expand.append((node.completed_by, tree))
                    else:
                        assert not node.is_non_terminal()
                        tree = MutableParseTree(node.state.rule_or_terminal)
                    for sibling in reversed(list(node.siblings())[1:]):
                        to_expand.append((sibling, parent))
                    if root is None:
                        root = tree
                    if parent is not None:
                        parent.children.append(tree)
                return root

            def is_non_terminal(self) -> bool:
                return not self.state.finished and isinstance(self.state.next_element, NonTerminal)

        for start_state in self.start_states:
            ns = NodeState(start_state)
            while True:
                yield ns.tree()
                if not ns.iterate():
                    break

    def _predict(self, state: EarleyState, k: int):
        prod: Production = self.grammar[state.next_element]  # type: ignore
        if not prod.can_produce_terminal:
            # Don't bother expanding this production because it can never produce a terminal
            new_state = EarleyState(
                production=state.production,
                parsed=state.parsed + (state.next_element,),
                expected=state.expected[1:],
                index=state.index
            )
            self.states[k].add(new_state, left_sibling=state)
            return
        for rule in prod.rules:
            new_state = EarleyState(production=prod, parsed=(), expected=rule.sequence, index=k, rule_or_terminal=rule)
            self.states[k].add(new_state, left_sibling=state)
            if not self.states[k].add(new_state, left_sibling=state):
                # we already encountered this state
                existing_state = self.states[k][new_state]
                # re-run a completion for it:
                self._complete(existing_state, k)

    def _scan(self, state: EarleyState, k: int) -> bool:
        expected_element = state.next_element
        terminal = expected_element.terminal  # type: ignore
        if not self.sentence[k:].startswith(terminal):
            return False
        new_state = EarleyState(
            production=state.production,
            parsed=state.parsed + (state.next_element,),
            expected=state.expected[1:],
            index=state.index,
            rule_or_terminal=expected_element,  # type: ignore
        )
        added = self.states[k + len(terminal)].add(new_state, left_sibling=state)
        assert added
        return True

    def _complete(self, completed: EarleyState, k: int):
        for state in self.states[completed.index].waiting_for[completed.production.name]:
            assert not state.finished
            assert isinstance(state.next_element, NonTerminal)
            assert state.next_element == completed.production.name
            new_state = EarleyState(
                production=state.production,
                parsed=state.parsed + completed.parsed,
                expected=state.expected[1:],
                index=state.index,
            )
            self.states[k].add(new_state, left_sibling=completed)
            state.completed_by.add(completed)


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
                            raise MissingProductionError(
                                f"Production {prod.name} references {v}, " "which is not in the grammar"
                            )
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
    elif isinstance(event, FunctionCall):
        return f"<{event.name}>"
    elif isinstance(event, FunctionReturn):
        return f"<{event.function_name}>"
    else:
        raise ValueError(f"Unhandled event: {event!r}")


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
            Production(grammar, prod_name, rule)

    grammar.start = grammar["<START>"]

    return grammar


def trace_to_grammar(trace: PolyTrackerTrace) -> Grammar:
    if trace.entrypoint is None:
        raise ValueError(f"Trace {trace} does not have an entrypoint!")

    # trace.simplify()

    grammar = Grammar()

    for event in tqdm(trace, unit=" productions", leave=False, desc="extracting a base grammar"):
        # ignore events before the entrypoint, if it exists
        if trace.entrypoint and trace.entrypoint.uid > event.uid:
            # if it's a function call to the entrypoint, that's okay
            if not isinstance(event, FunctionCall) or event.name != trace.entrypoint.function_name:
                continue

        prod_name = production_name(event)

        if isinstance(event, BasicBlockEntry):
            # Add a production rule for this BB

            sub_productions: List[Union[Terminal, str]] = [Terminal(token) for token in event.last_consumed_tokens]

            if event.called_function is not None:
                sub_productions.append(production_name(event.called_function))
                ret = event.called_function.function_return
                if ret is not None:
                    returning_to = event.called_function.returning_to
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

            if event.called_function is None and event.children:
                rules = [Rule(grammar, *(sub_productions + [f"<{child!s}>"])) for child in event.children]
            else:
                rules = [Rule(grammar, *sub_productions)]

            if prod_name in grammar:
                production = grammar[prod_name]
                for rule in rules:
                    if rule not in production:
                        production.add(rule)
            else:
                Production(grammar, prod_name, *rules)

        elif isinstance(event, FunctionCall):
            if event.entrypoint is None:
                if prod_name not in grammar:
                    Production(grammar, prod_name)
            else:
                rule = Rule(grammar, production_name(event.entrypoint))
                if prod_name in grammar:
                    production = grammar[prod_name]
                    if rule not in production:
                        production.add(rule)
                else:
                    Production(grammar, prod_name, rule)

        elif isinstance(event, FunctionReturn):
            next_event = event.returning_to
            if next_event is not None and not isinstance(next_event, BasicBlockEntry):
                # sometimes instrumentation errors can cause functions to return directly into another call
                call_name = production_name(event.function_call)
                next_event_name = production_name(next_event)
                if call_name in grammar:
                    production = grammar[call_name]
                    if not production.rules:
                        production.add(Rule(grammar, next_event_name))
                    else:
                        for rule in production.rules:
                            if next_event_name not in rule.sequence:
                                rule.sequence = rule.sequence + (next_event_name,)
                    grammar.used_by[next_event_name].add(call_name)
                else:
                    Production(grammar, call_name, Rule(grammar, next_event_name))

        if trace.entrypoint == event:
            grammar.start = Production(grammar, "<START>", Rule.load(grammar, f"<{event.function_name}>"))

    grammar.verify()

    return grammar


class TraceProperties:
    def __init__(
        self, unused_byte_offsets: List[int], out_of_order_byte_offsets: List[int], file_seeks: List[Tuple[int, int, int]]
    ):
        self.unused_byte_offsets: List[int] = unused_byte_offsets
        self.file_seeks: List[Tuple[int, int, int]] = file_seeks
        self.out_of_order_byte_offsets: List[int] = out_of_order_byte_offsets

    def __bool__(self):
        return not self.unused_byte_offsets and not self.out_of_order_byte_offsets and not self.file_seeks


def check_trace(trace: PolyTrackerTrace) -> TraceProperties:
    # check if the trace has taint data for all input bytes:
    first_usages: List[Optional[int]] = [None] * len(trace.inputstr)
    file_seeks: List[Tuple[int, int, int]] = []
    last_offset = None
    for i, (offset, _) in enumerate(trace.consumed_bytes()):
        if first_usages[offset] is None:
            first_usages[offset] = i
        if last_offset is not None:
            if offset < last_offset:
                file_seeks.append((i - 1, last_offset, offset))
        last_offset = offset
    unused_bytes = [offset for offset, first_used in enumerate(first_usages) if first_used is None]
    out_of_order = [
        previous_offset + 1
        for previous_offset, (previous, first_used) in enumerate(zip(first_usages, first_usages[1:]))
        if previous > first_used
    ]
    return TraceProperties(unused_byte_offsets=unused_bytes, out_of_order_byte_offsets=out_of_order, file_seeks=file_seeks)


def extract(traces: Iterable[PolyTrackerTrace]) -> Grammar:
    trace_iter = tqdm(traces, unit=" trace", desc=f"extracting traces", leave=False)
    for trace in trace_iter:
        properties = check_trace(trace)
        if properties.unused_byte_offsets:
            print(
                "Warning: The following byte offsets were never recorded as being read in the trace: "
                f"        {[(offset, trace.inputstr[offset:offset+1]) for offset in properties.unused_byte_offsets]!r}"
            )
        if properties.out_of_order_byte_offsets:
            print(
                "Warning: The trace read the following bytes out of order (implying that the trace is of a parser that "
                f"is not a pure recursive descent parser): {', '.join(map(str, properties.out_of_order_byte_offsets))}"
            )
        if properties.file_seeks:
            # this should only ever happen if properties.out_of_order_byte_offsets is also populated
            seeks = [f"⎆{i}:⎗{from_offset}→{to_offset}⎘" for i, from_offset, to_offset in properties.file_seeks]
            print(f"The parser backtracked from one offset to another at the following event indexes: {', '.join(seeks)}")
        tree = trace_to_non_generalized_tree(trace)
        match_before = tree.matches()
        tree.simplify()
        assert match_before == tree.matches() == trace.inputstr
        # TODO: Merge the grammars
        grammar = parse_tree_to_grammar(tree)  # trace_to_grammar(trace)
        assert bool(grammar.match(trace.inputstr))
        if False and __debug__:
            trace_iter.set_description("simplifying the grammar")
            grammar.simplify()
            m = grammar.match(trace.inputstr)
            if m:
                for tree in m:
                    print(tree)
        return grammar
    return Grammar()
