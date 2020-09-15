import itertools
from abc import ABCMeta, abstractmethod
from collections import defaultdict
from typing import Any, BinaryIO, cast, Dict, Generic, Iterable, Iterator, List, Optional, Set, Tuple, TypeVar, Union

import networkx as nx
from tqdm import tqdm, trange

from .cfg import DiGraph
from .parsing import highlight_offset, NonGeneralizedParseTree, ParseTree, Start, Terminal, trace_to_non_generalized_tree
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
            yield PartialMatch(tree=ParseTree(self), remaining_symbols=(), remaining_bytes=sentence)
            return
        for rule in self.rules:

            def make_tree() -> Tuple[ParseTree[ParseTreeValue], ParseTree[ParseTreeValue]]:
                root: ParseTree[ParseTreeValue] = ParseTree(self)
                rtree: ParseTree[ParseTreeValue] = ParseTree(rule)
                root.children.append(rtree)  # type: ignore
                return root, rtree

            stack: List[Tuple[bytes, List[ParseTree[ParseTreeValue]], List[Symbol]]] = [(sentence, [], list(rule.sequence))]
            while stack:
                remaining_bytes, trees, remaining_symbols = stack.pop()
                if not remaining_symbols or not remaining_bytes:
                    root_tree, rule_tree = make_tree()
                    if not rule_tree.children:
                        if not trees:
                            trees = [ParseTree(Terminal(""))]
                        rule_tree.children = trees  # type: ignore
                    yield PartialMatch(
                        tree=root_tree, remaining_symbols=tuple(remaining_symbols), remaining_bytes=remaining_bytes
                    )
                else:
                    next_symbol = remaining_symbols[0]
                    if isinstance(next_symbol, Terminal):
                        if remaining_bytes == next_symbol.terminal:
                            root_tree, rule_tree = make_tree()
                            rule_tree.children = trees + [ParseTree(next_symbol)]  # type: ignore
                            yield PartialMatch(
                                tree=root_tree, remaining_symbols=tuple(remaining_symbols[1:]), remaining_bytes=b""
                            )
                        elif remaining_bytes.startswith(next_symbol.terminal):
                            stack.append(
                                (
                                    remaining_bytes[len(next_symbol.terminal) :],
                                    trees + [ParseTree(next_symbol)],
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

    @property
    def can_produce_terminal(self) -> bool:
        if self._can_produce_terminal is None:
            with tqdm(leave=False, unit=" productions") as status:
                status.set_description("building grammar dependency graph")
                graph: DiGraph = self.grammar.dependency_graph()
                status.total = len(graph)
                status.set_description("calculating dominator forest")
                forest = graph.dominator_forest
                status.set_description("finding empty productions")
                for production in nx.dfs_postorder_nodes(forest):
                    status.update(1)
                    # use a postorder traversal so dependencies are calculated first
                    cast(Production, production)._propagate_terminals()
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
    __slots__ = ["production", "parsed", "expected", "index", "potential_predecessors"]

    def __init__(self, production: Production, parsed: Tuple[Symbol, ...], expected: Tuple[Symbol, ...], index: int):
        self.production: Production = production
        self.parsed: Tuple[Symbol, ...] = parsed
        self.expected: Tuple[Symbol, ...] = expected
        self.index: int = index
        self.potential_predecessors: Set[EarleyState] = set()

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

    def add(self, state: EarleyState) -> bool:
        if state in self.elements:
            # We already have this state
            return False
        self.queue.append(state)
        self.elements[state] = state
        if not state.finished and isinstance(state.next_element, NonTerminal):
            self.waiting_for[state.next_element].add(state)
        return True

    def __contains__(self, item):
        return item in self.elements

    def __getitem__(self, state: EarleyState) -> EarleyState:
        return self.elements[state]

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

    def parse(self) -> Iterator[ParseTree[ParseTreeValue]]:
        for rule in self.start.rules:
            self.states[0].add(EarleyState(production=self.start, parsed=(), expected=rule.sequence, index=0))
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
        return self.parse_trees()

    def parse_trees(self) -> Iterator[ParseTree[ParseTreeValue]]:
        """Reconstructs all parse trees from the parse. This must be called after a call to self.parse()"""
        states = self.states

        class SearchNode:
            def __init__(self, state: EarleyState, parent: Optional['SearchNode'] = None):
                self.state: EarleyState = state
                self.parent: Optional[SearchNode] = parent
                if parent is None:
                    self.k = len(states) - 1
                else:
                    self.k = parent.k - 1

            def successors(self) -> Iterator['SearchNode']:
                if self.k == 0:
                    return
                for state in self.state.potential_predecessors:
                    yield SearchNode(state, self)

            def is_complete(self) -> bool:
                return self.k == 0

            def ancestors(self) -> Iterator['SearchNode']:
                p = self.parent
                while p:
                    yield p
                    p = p.parent

            def tree(self) -> ParseTree[ParseTreeValue]:
                root = ParseTree(self.state.production)
                node = root
                for state in self.ancestors():
                    new_node = ParseTree(state.production)
                    node.children.append(new_node)
                    node = new_node
                return root

        states: List[SearchNode] = [SearchNode(state) for state in self.states[-1]]
        while states:
            s = states.pop()
            if s.is_complete():
                yield s.tree()
            else:
                states.extend(s.successors())

    def _predict(self, state: EarleyState, k: int):
        prod: Production = self.grammar[state.next_element]  # type: ignore
        if not prod.rules:
            new_state = EarleyState(production=prod, parsed=(prod.name,), expected=(), index=k)
            if not self.states[k].add(new_state):
                # we already encountered this state, so re-run a completion for it:
                self._complete(new_state, k)
        else:
            for rule in prod.rules:
                new_state = EarleyState(production=prod, parsed=(), expected=rule.sequence, index=k)
                if not self.states[k].add(new_state):
                    # we already encountered this state, so re-run a completion for it:
                    self._complete(new_state, k)

    def _scan(self, state: EarleyState, k: int) -> bool:
        expected_element = state.next_element
        terminal = expected_element.terminal  # type: ignore
        if not self.sentence[k:].startswith(terminal):
            return False
        self.states[k + len(terminal)].add(
            EarleyState(
                production=state.production,
                parsed=state.parsed + (state.next_element,),
                expected=state.expected[1:],
                index=state.index,
            )
        )
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
                index=state.index
            )
            self.states[k].add(new_state)


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


def extract(traces: Iterable[PolyTrackerTrace]) -> Grammar:
    trace_iter = tqdm(traces, unit=" trace", desc=f"extracting traces", leave=False)
    for trace in trace_iter:
        # check if the trace has taint data for all input bytes:
        unused_bytes = set(range(len(trace.inputstr)))
        for offset, _ in trace.consumed_bytes():
            try:
                unused_bytes.remove(offset)
            except KeyError:
                pass
        if unused_bytes:
            print(
                "Warning: The following byte offsets were never recorded as being read in the trace: "
                f"        {[(offset, trace.inputstr[offset:offset+1]) for offset in sorted(unused_bytes)]!r}"
            )
        tree = trace_to_non_generalized_tree(trace)
        match_before = tree.matches()
        tree.simplify()
        assert match_before == tree.matches() == trace.inputstr
        # TODO: Merge the grammars
        grammar = parse_tree_to_grammar(tree)  # trace_to_grammar(trace)
        print(grammar)
        if __debug__:
            m = grammar.match(trace.inputstr)
            if m:
                for tree in m:
                    print(tree)
        trace_iter.set_description("simplifying the grammar")
        grammar.simplify()
        print(grammar)
        return grammar
    return Grammar()


def decl_datalog_fact(name) -> str:
    return f".decl {name}(x: number, y: number)\n"


def gen_datalog_fact(name, start, end) -> str:
    return f"{name}({start}, {end}).\n"


# TODO we might be able to also get this from a trace
# TODO might need to swap from str to input file.
# But I think indexing the entire input file is actually fine for now
def extract_datalog_facts(input_file: BinaryIO) -> str:
    # Keep track unique bytes in the file and their occurences
    unique_bytes: Dict[int, bool] = {}
    # Datalog code to return :)
    # Turn this into class with @property str
    datalog_code = ""
    with open(input_file.name, "rb") as file:
        data = file.read()
        for i, byte in enumerate(data):
            # Declare the new type of byte
            if byte not in unique_bytes:
                if chr(byte) == "":
                    continue
                else:
                    datalog_code += decl_datalog_fact(f"GEN_{byte}")
                unique_bytes[byte] = True
            if chr(byte) == "":
                continue
            else:
                datalog_code += gen_datalog_fact(f"GEN_{byte}", i, i + 1)
    return datalog_code


def decl_datalog_prod_rule(name):
    val_list = list(map(ord, name))
    val_list = list(map(str, val_list))
    return f".decl GEN_{'_'.join(val_list)}(x: number, y: number)\n .output GEN_{'_'.join(val_list)}\n"


def decl_output_prod_rule(name):
    val_list = list(map(ord, name))
    val_list = list(map(str, val_list))
    return f".output GEN_{'_'.join(val_list)}\n"


def gen_datalog_clause(name, start, end):
    val_list = list(map(ord, name))
    val_list = list(map(str, val_list))
    name = "_".join(val_list)
    return f"GEN_{name}({start}, {end})"


def extract_datalog_grammar(traces: Iterable[PolyTrackerTrace], input_files) -> str:
    datalog_facts = ""
    datalog_grammar = ""
    datalog_parser_grammar = ""
    unique_rules: Dict[str, bool] = {}
    trace_iter = tqdm(traces, unit=" trace", desc=f"extracting traces", leave=False)
    for i, trace in enumerate(trace_iter):
        datalog_facts += extract_datalog_facts(input_files[i])
        # TODO: Merge the grammars
        grammar = trace_to_grammar(trace)
        # grammar.match(trace.inputstr)
        trace_iter.set_description("simplifying the grammar")
        grammar.simplify()
        # print("Start symbol!", grammar.start.name)
        # grammar.productions
        for prod_name in grammar.productions:
            # print("prod name", prod_name)
            if prod_name not in unique_rules:
                unique_rules[prod_name] = True
                datalog_grammar += decl_datalog_prod_rule(prod_name)
                if "<START>" in prod_name:
                    datalog_grammar += decl_output_prod_rule(prod_name)

            # datalog_sentence = f"{prod_name}(i, j) :- "
            # Start the variable iteration at "a", which is 97.
            # As we add new rules in the sequence, we need to add new free variables to the datalog.
            var_iterator_start = 97
            var_iterator_curr = var_iterator_start
            datalog_clause_terms = []
            for rule in grammar.productions[prod_name].rules:
                for term in rule.sequence:
                    # if its a production rule, check if we have seen it before.
                    if isinstance(term, str):
                        # TODO maybe can do this whenever they are encountered in prod
                        if term not in unique_rules:
                            unique_rules[term] = True
                            datalog_grammar += decl_datalog_prod_rule(term)

                        datalog_clause_terms.append(
                            gen_datalog_clause(term, chr(var_iterator_curr), chr(var_iterator_curr + 1))
                        )
                        var_iterator_curr += 1

                    # If its a terminal, we must make sure the name matches that of the fact.
                    elif isinstance(term, Terminal):
                        # print("term is a TERMINAL?", term)
                        for val in term.terminal:
                            if chr(val) == "":
                                continue
                            datalog_clause_terms.append(
                                f"GEN_{val}({chr(var_iterator_curr)}, " f"{chr(var_iterator_curr + 1)})"
                            )
                            var_iterator_curr += 1
                    else:
                        print(f"WARNING term is not string/terminal: {term}")
                # Add the end of the rule.
            datalog_clause_terms[len(datalog_clause_terms) - 1] += "."
            val_list: List[int] = list(map(ord, prod_name))
            val_list_str: List[str] = list(map(str, val_list))
            head_name = f"GEN_{'_'.join(val_list_str)}"
            datalog_parser_grammar += (
                f"{head_name}({chr(var_iterator_start)},{chr(var_iterator_curr)}) :- " f"{', '.join(datalog_clause_terms)}\n"
            )

    return datalog_facts + "\n" + datalog_grammar + "\n" + datalog_parser_grammar
