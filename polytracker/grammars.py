from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union

from tqdm import tqdm

from .tracing import BasicBlockEntry, FunctionCall, PolyTrackerTrace


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

    def remove_sub_production(self, production_name: str) -> bool:
        old_len = len(self.sequence)
        self.sequence = tuple([s for s in self.sequence if s != production_name])
        return len(self.sequence) != old_len

    def replace_sub_production(self, to_replace: str, replace_with: str):
        new_seq = []
        for s in self.sequence:
            if s == to_replace:
                new_seq.append(replace_with)
            else:
                new_seq.append(s)
        self.sequence = tuple(new_seq)

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

    def first_rule(self) -> Optional[Rule]:
        if self.rules:
            return next(iter(self.rules))
        else:
            return None

    def remove_sub_production(self, production_name: str):
        new_rules = []
        for rule in self.rules:
            rule.remove_sub_production(production_name)
            if rule:
                new_rules.append(rule)
        self.rules = set(new_rules)

    def replace_sub_production(self, to_replace: str, replace_with: str):
        for rule in list(self.rules):
            self.rules.remove(rule)
            rule.replace_sub_production(to_replace, replace_with)
            self.rules.add(rule)

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
        return f"{self.name} ::= {rules}"


class Grammar:
    def __init__(self):
        self.productions: Dict[str, Production] = {}
        self.used_by: Dict[str, Set[str]] = defaultdict(set)
        self.start: Optional[Production] = None

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
        del self.productions[name]
        for uses_name in self.used_by[name]:
            if uses_name in self:
                self[uses_name].remove_sub_production(name)
        del self.used_by[name]
        return True

    def simplify(self) -> bool:
        modified = False
        modified_last_pass = True
        while modified_last_pass:
            modified_last_pass = False
            for prod in list(self.productions.values()):
                if not prod.rules:
                    # remove any produtions that only produce empty strings
                    removed = self.remove(prod)
                    assert removed
                    modified_last_pass = True
                elif len(prod.rules) == 1 and len(prod.first_rule().sequence) == 1 and isinstance(prod.first_rule().sequence[0], str):
                    # this production has a single rule that just calls another production,
                    # so replace it with that production
                    equivalent_prod_name: str = prod.first_rule().sequence[0]
                    for uses_name in self.used_by[prod.name]:
                        if uses_name in self:
                            self[uses_name].replace_sub_production(prod.name, equivalent_prod_name)
                    del self.productions[prod.name]
                    del self.used_by[prod.name]
                    modified_last_pass = True
                elif prod != self.start and not self.used_by[prod.name]:
                    # this production isn't used by anything, so remove it
                    self.remove(prod)
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


def trace_to_grammar(trace: PolyTrackerTrace) -> Grammar:
    if trace.entrypoint is None:
        raise ValueError(f"Trace {trace} does not have an entrypoint!")

    # trace.simplify()

    grammar = Grammar()

    for event in tqdm(trace, unit=" productions", leave=False, desc="extracting a base grammar"):
        if isinstance(event, BasicBlockEntry):
            # Add a production rule for this BB

            sub_productions: List[str] = []

            for token in event.consumed_tokens:
                # Make a production rule for this terminal, or add one if it already exists:
                terminal = Terminal(token)
                terminal_name = f"<{terminal!s}>"
                if terminal_name not in grammar:
                    Production(grammar, terminal_name, Rule(grammar, terminal))
                sub_productions.append(terminal_name)

            if event.called_function is not None:
                sub_productions.append(f"<{event.called_function.name}>")
                ret = event.called_function.function_return
                if ret is not None:
                    returning_to = event.called_function.function_return.returning_to
                    if returning_to is not None:
                        sub_productions.append(f"<{returning_to!s}>")
                    else:
                        # TODO: Print warning
                        pass
                else:
                    # TODO: Print warning
                    pass

            if event.children:
                rules = [Rule(grammar, *(sub_productions + [f"<{child!s}>"])) for child in event.children]
            else:
                rules = [Rule(grammar, *sub_productions)]

            production_name = f"<{event!s}>"
            if production_name in grammar:
                production = grammar[production_name]
                for rule in rules:
                    if rule not in production:
                        production.add(rule)
            else:
                Production(grammar, production_name, *rules)

        elif isinstance(event, FunctionCall):
            if event.entrypoint is None:
                print(f"Warning: unknown basic block entrypoint for function {event.name}")
            else:
                production_name = f"<{event.name}>"
                rule = Rule(grammar, str(event.entrypoint))
                if production_name in grammar:
                    production = grammar[production_name]
                    if rule not in production:
                        production.add(rule)
                else:
                    Production(grammar, production_name, rule)

        if trace.entrypoint == event:
            grammar.start = Production(grammar, "<START>", Rule.load(grammar, f"<{event!s}>"))

    return grammar


def extract(traces: Iterable[PolyTrackerTrace]) -> Grammar:
    # trees = [{'tree': list(tree)} for tree in miner(traces)]
    # gmethod_trees = generalize_method_trees(trees)
    # print(json.dumps(gmethod_trees, indent=4))
    for trace in traces:
        # TODO: Merge the grammars
        grammar = trace_to_grammar(trace)
        grammar.simplify()
        return grammar
