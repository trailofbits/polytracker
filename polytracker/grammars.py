import heapq
import itertools
from argparse import ArgumentParser, Namespace
from collections import defaultdict
from logging import getLogger
from typing import (
    Any,
    cast,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Union,
)

# TODO remove
import graphviz
import networkx as nx
from tqdm import tqdm

from . import PolyTrackerTrace
from .cfg import DiGraph
from .plugins import Command
from .repl import PolyTrackerREPL
from .tracing import (
    BasicBlockEntry,
    FunctionEntry,
    FunctionReturn,
    ProgramTrace,
    TraceEvent,
)


log = getLogger("grammars")


class Terminal:
    def __init__(self, terminal: Union[bytes, str]):
        if isinstance(terminal, str):
            terminal = terminal.encode("utf-8")
        self.terminal: bytes = terminal

    def __add__(self, other: Union[bytes, str, "Terminal"]) -> "Terminal":
        if isinstance(other, Terminal):
            other = other.terminal
        elif isinstance(other, str):
            other = other.encode("utf-8")
        return Terminal(self.terminal + other)

    def __eq__(self, other):
        return isinstance(other, Terminal) and other.terminal == self.terminal

    def __hash__(self):
        return hash(self.terminal)

    def __repr__(self):
        return f"{self.__class__.__name__}(terminal={self.terminal!r})"

    def __str__(self):
        ret = '"'
        for i in self.terminal:
            if i == ord("\n"):
                b = "\\n"
            elif i == ord("\t"):
                b = "\\t"
            elif i == ord("\r"):
                b = "\\r"
            elif i == ord('"'):
                b = '\\"'
            elif i == ord("\\"):
                b = "\\\\"
            elif ord(" ") <= i <= ord("~"):
                b = chr(i)
            else:
                b = f"\\x{i:02x}"
            ret = f"{ret}{b}"
        return f'{ret}"'


class Rule:
    def __init__(self, grammar: "Grammar", *sequence: Union[Terminal, str]):
        self.grammar: Grammar = grammar
        self.sequence: Tuple[Union[Terminal, str], ...] = Rule.combine_terminals(
            sequence
        )
        self.has_terminals: bool = any(isinstance(t, Terminal) for t in self.sequence)

    @staticmethod
    def combine_terminals(
        sequence: Iterable[Union[Terminal, str]]
    ) -> Tuple[Union[Terminal, str], ...]:
        seq: List[Union[Terminal, str]] = []
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
        return self.has_terminals or any(
            p.can_produce_terminal for p in self if isinstance(p, Production)
        )

    def remove_sub_production(self, prod_name: str) -> bool:
        old_len = len(self.sequence)
        self.sequence = Rule.combine_terminals(
            [s for s in self.sequence if s != prod_name]
        )
        return len(self.sequence) != old_len

    def replace_sub_production(
        self, to_replace: str, replace_with: Union[str, "Rule"]
    ) -> bool:
        if isinstance(replace_with, str):
            if to_replace == replace_with:
                return False
            replacement: List[Union[str, Terminal]] = [replace_with]
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
    def load(grammar: "Grammar", *sequence: Union[Terminal, str]) -> "Rule":
        alts: List[Union[Terminal, str]] = []
        for a in sequence:
            if isinstance(a, str):
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
            raise ValueError(
                f"A production named {name!r} already exists in grammar {grammar!s}!"
            )
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

    @property
    def can_produce_terminal(self) -> bool:
        if self._can_produce_terminal is None:
            with tqdm(leave=False, unit=" productions", delay=1.0) as status:
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

    def replace_sub_production(self, to_replace: str, replace_with: Union[str, Rule]):
        if isinstance(replace_with, str):
            if to_replace == replace_with:
                return
            new_prods: List[str] = [replace_with]
            replace_with = Rule(self.grammar, replace_with)
        else:
            new_prods = [v for v in replace_with.sequence if isinstance(v, str)]
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
            if isinstance(term, str):
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


class ParseTree:
    def __init__(self, production_or_terminal: Union[Production, Terminal]):
        self.value: Union[Production, Terminal] = production_or_terminal
        self.children: List[ParseTree] = []

    def __iter__(self) -> Iterator["ParseTree"]:
        return iter(self.children)

    def __len__(self):
        return len(self.children)

    def __str__(self):
        if not self.children:
            return str(self.value)
        else:
            return f"[{self.value!s} [{' '.join(map(str, self.children))}]]"


class MatchPossibility:
    def __init__(
        self,
        grammar: "Grammar",
        remainder: bytes,
        production: Production,
        rule: Rule,
        after_sequence: Iterable[Tuple["MatchPossibility", Union[str, Terminal]]] = (),
        previous: Optional["MatchPossibility"] = None,
        parent: Optional["MatchPossibility"] = None,
    ):
        self.grammar: "Grammar" = grammar
        self.remainder: bytes = remainder
        self.rule: Rule = rule
        self.sequence: List[Tuple["MatchPossibility", Union[str, Terminal]]] = [
            (self, s) for s in rule.sequence
        ] + list(after_sequence)
        self.previous: Optional[MatchPossibility] = previous
        self.parent: Optional[MatchPossibility] = parent
        self.production: Production = production
        self._consumed: Optional[List[Tuple["MatchPossibility", Terminal]]] = None
        if previous is None:
            self.depth: int = 0
        else:
            self.depth = previous.depth + 1

    @property
    def consumed(self) -> List[Tuple["MatchPossibility", Terminal]]:
        if self._consumed is None:
            # running self.expand() automatically sets self._consumed
            _ = self.expand()
        return self._consumed  # type: ignore

    def __lt__(self, other: "MatchPossibility"):
        return (self.depth < other.depth) or (
            self.depth == other.depth and len(self.remainder) < len(other.remainder)
        )

    def expand(self) -> Optional[List["MatchPossibility"]]:
        possibilities = []
        remainder = self.remainder
        matches = 0
        if self._consumed is None:
            self._consumed = []
            assign_consumed = True
        else:
            assign_consumed = False
        for source, seq in self.sequence:
            if isinstance(seq, Terminal):
                if not remainder.startswith(seq.terminal):
                    return None
                remainder = remainder[len(seq.terminal):]
                if assign_consumed:
                    self._consumed.append((source, seq))
                matches += 1
            else:
                break
        if matches == len(self.sequence):
            return []
        parent, next_production = self.sequence[matches]
        assert isinstance(next_production, str)
        production = self.grammar[next_production]
        rules: Iterable[Rule] = production.rules
        if not rules:
            rules = [Rule(self.grammar)]
        for rule in rules:
            possibilities.append(
                MatchPossibility(
                    grammar=self.grammar,
                    remainder=remainder,
                    production=production,
                    rule=rule,
                    after_sequence=self.sequence[matches + 1:],
                    parent=parent,
                    previous=self,
                )
            )
        return possibilities


class Grammar:
    def __init__(self):
        self.productions: Dict[str, Production] = {}
        self.used_by: Dict[str, Set[str]] = defaultdict(set)
        self.start: Optional[Production] = None

    def match(
        self, sentence: Union[str, bytes], start: Optional[Production] = None
    ) -> ParseTree:
        if isinstance(sentence, str):
            sentence = sentence.encode("utf-8")
        if start is None:
            if self.start is None:
                raise ValueError(
                    "Either the grammar must have a start production or one must be provided to `match`"
                )
            start = self.start
        possibilities = [
            MatchPossibility(
                grammar=self, remainder=sentence, production=start, rule=rule
            )
            for rule in start.rules
        ]
        while possibilities:
            possibility = heapq.heappop(possibilities)
            print(possibility.production)
            sub_possibilities = possibility.expand()
            if sub_possibilities is not None:
                if len(sub_possibilities) == 0:
                    # we found a match!
                    # TODO: Convert this to a ParseTree
                    return possibility  # type:ignore
                for p in sub_possibilities:
                    heapq.heappush(possibilities, p)
        # TODO: Describe this parse error
        raise ValueError()

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

    def remove(self, production: Union[str, Production]) -> bool:
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
                if isinstance(v, str):
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
                                f"Production {prod.name} references {v}, which is not in the grammar"
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
                raise CorruptedGrammarError(
                    f'Production {prod_name} is in the "used by" table, but not in the grammar'
                )
        if self.start is not None and test_disconnection:
            # make sure there is a path from start to every other production
            graph = self.dependency_graph()
            visited = set(
                node for node in nx.dfs_preorder_nodes(graph, source=self.start)
            )
            if len(visited) < len(self.productions):
                not_visited_prods = set(
                    node for node in self.productions.values() if node not in visited
                )
                # it's okay if the unvisited productions aren't able to produce terminals
                not_visited = [
                    node.name for node in not_visited_prods if node.can_produce_terminal
                ]
                if not_visited:
                    raise DisconnectedGrammarError(
                        "These productions are not accessible from the start production "
                        f"{self.start.name}: {', '.join(not_visited)}"
                    )

    def simplify(self) -> bool:
        modified = False
        modified_last_pass = True
        with tqdm(
            desc="garbage collecting", unit=" productions", leave=False, unit_divisor=1
        ) as status:
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
            ordered_productions: List[Production] = list(
                nx.dfs_postorder_nodes(dominators, source=self.start)
            )
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
    elif isinstance(event, FunctionEntry):
        return f"<{event.function.name}>"
    elif isinstance(event, FunctionReturn):
        return f"<{event.function.name}>"
    else:
        raise ValueError(f"Unhandled event: {event!r}")


def trace_to_grammar(trace: ProgramTrace) -> Grammar:
    # trace.simplify()

    grammar = Grammar()

    for event in tqdm(
        trace, unit=" productions", leave=False, desc="extracting a base grammar"
    ):
        if isinstance(event, BasicBlockEntry):
            # Add a production rule for this BB
            prod_name = production_name(event)

            sub_productions: List[Union[Terminal, str]] = [
                Terminal(token) for token in event.consumed_tokens
            ]

            called_function = event.called_function

            if called_function is not None:
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

            next_bb = event.next_basic_block_in_function()
            if next_bb is not None:
                rules = [Rule(grammar, *(sub_productions + [f"<{next_bb!s}>"]))]
            else:
                rules = [Rule(grammar, *sub_productions)]

            if prod_name in grammar:
                production = grammar[prod_name]
                for rule in rules:
                    if rule not in production:
                        production.add(rule)
            else:
                Production(grammar, prod_name, *rules)

        elif isinstance(event, FunctionEntry):
            prod_name = production_name(event)
            if event.entrypoint is None:
                if prod_name not in grammar:
                    _ = Production(grammar, prod_name)
            else:
                rule = Rule(grammar, production_name(event.entrypoint))
                if prod_name in grammar:
                    production = grammar[prod_name]
                    if rule not in production:
                        production.add(rule)
                else:
                    _ = Production(grammar, prod_name, rule)

            if grammar.start is None:
                grammar.start = Production(
                    grammar, "<START>", Rule.load(grammar, prod_name)
                )

        # elif isinstance(event, FunctionReturn):
        #     next_event = event.returning_to
        #     if next_event is not None and not isinstance(next_event, BasicBlockEntry):
        #         # sometimes instrumentation errors can cause functions to return directly into another call
        #         call_name = production_name(event.function_call)
        #         next_event_name = production_name(next_event)
        #         if call_name in grammar:
        #             production = grammar[call_name]
        #             if not production.rules:
        #                 production.add(Rule(grammar, next_event_name))
        #             else:
        #                 for rule in production.rules:
        #                     if next_event_name not in rule.sequence:
        #                         rule.sequence = rule.sequence + (next_event_name,)
        #             grammar.used_by[next_event_name].add(call_name)
        #         else:
        #             _ = Production(grammar, call_name, Rule(grammar, next_event_name))

    grammar.verify()

    return grammar


@PolyTrackerREPL.register("extract_grammar")
def extract(traces: Iterable[ProgramTrace], simplify: bool = False) -> Grammar:
    """extract a grammar from a set of traces"""
    trace_iter = tqdm(traces, unit=" trace", desc="extracting traces", leave=False)
    for trace in trace_iter:
        # TODO: Merge the grammars
        grammar = trace_to_grammar(trace)
        # grammar.match(trace.inputstr)
        trace_iter.set_description("simplifying the grammar")
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
        parser.add_argument(
            "--simplify", "-s", action="store_true", help="simplify the grammar"
        )

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
