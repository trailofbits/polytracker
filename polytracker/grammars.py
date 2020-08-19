import itertools
from collections import defaultdict
from typing import Any, cast, Dict, Iterable, List, Optional, Set, Tuple, Union

import networkx as nx
from tqdm import tqdm

from .cfg import DiGraph
from .tracing import BasicBlockEntry, FunctionCall, FunctionReturn, PolyTrackerTrace, TraceEvent


class Terminal:
    def __init__(self, terminal: Union[bytes, str]):
        if isinstance(terminal, str):
            terminal = terminal.encode("utf-8")
        self.terminal: bytes = terminal

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
        self.sequence: Tuple[Union[Terminal, str], ...] = tuple(sequence)
        self.has_terminals: bool = any(isinstance(t, Terminal) for t in self.sequence)

    @property
    def can_produce_terminal(self) -> bool:
        return self.has_terminals or any(p.can_produce_terminal for p in self if isinstance(p, Production))

    def remove_sub_production(self, production_name: str) -> bool:
        old_len = len(self.sequence)
        self.sequence = tuple([s for s in self.sequence if s != production_name])
        return len(self.sequence) != old_len

    def replace_sub_production(self, to_replace: str, replace_with: Union[str, "Rule"]) -> bool:
        if isinstance(replace_with, str):
            replacement = [replace_with]
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
            self.sequence = tuple(new_seq)
        return modified

    def __hash__(self):
        return hash(self.sequence)

    def __eq__(self, other):
        return self.sequence == other.sequence

    @staticmethod
    def load(grammar: "Grammar", *sequence: Union[Terminal, str]) -> "Rule":
        alts = []
        for a in sequence:
            if isinstance(a, str):
                if a.startswith("<") and a.endswith(">"):
                    alts.append(a)
                else:
                    alts.append(Terminal(a))
            else:
                alts.append(a)
        return Rule(grammar, *alts)

    def __iter__(self) -> Iterable[Union[Terminal, "Production"]]:
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
        self.rules: Set[Rule, ...] = set(rules)
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
        return self._can_produce_terminal

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

    def remove_sub_production(self, production_name: str):
        new_rules = []
        for rule in self.rules:
            rule.remove_sub_production(production_name)
            if rule:
                new_rules.append(rule)
        self.rules = set(new_rules)
        self.grammar.used_by[production_name].remove(self.name)

    def replace_sub_production(self, to_replace: str, replace_with: Union[str, Rule]):
        if isinstance(replace_with, str):
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
        return Production(grammar, name, *(Rule.load(grammar, *alternatives) for alternatives in rules))

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

    def __iter__(self) -> Iterable[Rule]:
        return iter(self.rules)

    def __len__(self):
        return len(self.rules)

    def __str__(self):
        rules = " | ".join(map(str, self.rules))
        if self.grammar.start is self:
            start = "--> "
        else:
            start = ""
        return f"{start}{self.name} ::= {rules}"


class GrammarError(RuntimeError):
    pass


class CorruptedGrammarError(GrammarError):
    pass


class MissingProductionError(CorruptedGrammarError):
    pass


class Grammar:
    def __init__(self):
        self.productions: Dict[str, Production] = {}
        self.used_by: Dict[str, Set[str]] = defaultdict(set)
        self.start: Optional[Production] = None

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
        else:
            name = production
        if name not in self:
            return False
        # update all of the productions we use
        for rule in production:
            for v in rule.sequence:
                if isinstance(v, str):
                    try:
                        self.used_by[v].remove(name)
                    except KeyError:
                        pass
        del self.productions[name]
        # update all of the productions that use us
        for uses_name in list(self.used_by[name]):
            self[uses_name].remove_sub_production(name)
        del self.used_by[name]
        return True

    def verify(self):
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
                        f"Production {prod.name} is used by {user}, but {user} production is " "not in the grammar"
                    )
            if not self.used_by[prod.name] and self.start is not prod:
                print(f"Warning: Production {prod.name} is never used")

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
                        # self.verify()
                        status.update(1)
                        modified_last_pass = True
                    elif len(prod.rules) == 1 and prod is not self.start:
                        # this production has a single rule, so replace all uses with that rule
                        for user in list(prod.used_by):
                            user.replace_sub_production(prod.name, prod.first_rule())
                        self.remove(prod)
                        # self.verify()
                        status.update(1)
                        modified_last_pass = True
                modified = modified or modified_last_pass
            return modified

    def __len__(self):
        return len(self.productions)

    def __iter__(self) -> Iterable[Production]:
        yield from self.productions.values()

    def __getitem__(self, production_name: str):
        return self.productions[production_name]

    def __contains__(self, production_name: str):
        return production_name in self.productions

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


def trace_to_grammar(trace: PolyTrackerTrace) -> Grammar:
    if trace.entrypoint is None:
        raise ValueError(f"Trace {trace} does not have an entrypoint!")

    # trace.simplify()

    grammar = Grammar()

    for event in tqdm(trace, unit=" productions", leave=False, desc="extracting a base grammar"):
        prod_name = production_name(event)

        if isinstance(event, BasicBlockEntry):
            # Add a production rule for this BB

            sub_productions: List[Union[Terminal, str]] = [Terminal(token) for token in event.consumed_tokens]

            if event.called_function is not None:
                sub_productions.append(production_name(event.called_function))
                ret = event.called_function.function_return
                if ret is not None:
                    returning_to = event.called_function.function_return.returning_to
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
        # TODO: Merge the grammars
        grammar = trace_to_grammar(trace)
        trace_iter.set_description("simplifying the grammar")
        grammar.simplify()
        return grammar
