from argparse import ArgumentParser, Namespace
from typing import List, Dict, Union

from .grammars import (
    ExtractGrammarCommand,
    Terminal,
    ProgramTrace,
    trace_to_grammar,
)
from .plugins import CommandExtension

import re


TRUE_FACT_NAME = "POLYTRACKER_TRUE_FACT"


# Replaces non alpha numeric characters with their numerical value.
def datalog_repl_match(matched_str) -> str:
    ret_str = ""
    # TODO replace with join?
    for char in matched_str.group():
        ret_str += f"_{ord(char)}"
    return ret_str


def get_valid_datalog_name(name):
    return f"GEN_{re.sub('[^a-zA-Z0-9]', datalog_repl_match, name)}"


class DatalogTrueFactDecl:
    """
    This is a fact that will always be true. This is our datalog equivalent of epislon productions
    """

    def __init__(self):
        self.name = get_valid_datalog_name(TRUE_FACT_NAME)

    @property
    def val(self) -> str:
        return f".decl {self.name}(x: number)"


class DatalogTrueFact:
    def __init__(self, index):
        self.name = get_valid_datalog_name(TRUE_FACT_NAME)
        self.index = index

    @property
    def val(self) -> str:
        return f"{self.name}({self.index})"

    @property
    def end_char(self) -> str:
        return self.index


class DatalogFactDecl:
    """
    These are the fact declarations from reading over file input bytes
    x --> start location
    y --> end location
    """

    def __init__(self, byte: str):
        self.name = get_valid_datalog_name(byte)

    @property
    def val(self) -> str:
        return f".decl {self.name}(x: number, y: number)"


class DatalogFact:
    """
    These are the facts that are created via the indexing of the input file
    GEN_ByteVal(0, 1) for the byte at location 0 in the file
    """

    def __init__(self, name: str, start_pos: int, end_pos: int):
        self.name = get_valid_datalog_name(name)
        self.start_pos = start_pos
        self.end_pos = end_pos

    @property
    def val(self) -> str:
        return f"{self.name}({self.start_pos}, {self.end_pos})."


class DatalogRule:
    """
    This is a datalog rule, an instance of some Name(a, b)
    """

    def __init__(self, name: str, start_char: str = "a", end_char: str = "a"):
        self.name = get_valid_datalog_name(name)
        self.start_char = start_char
        self.end_char = end_char

    @property
    def val(self) -> str:
        return f"{self.name}({self.start_char}, {self.end_char})"


class DatalogOutputDecl:
    """
    Tells the datalog parser to output information about this production rule
    into csv. We always output <START>
    """

    def __init__(self, name: str):
        self.name = get_valid_datalog_name(name)

    @property
    def val(self) -> str:
        return f".output {self.name}"


class DatalogRuleDecl:
    """
    This just forward declares a production rule by defining its arguemnts
    Name(a: number, b: number)
    """

    def __init__(self, name: str):
        self.name = get_valid_datalog_name(name)

    @property
    def val(self) -> str:
        return f".decl {self.name}(x: number, y: number)"


class DatalogRuleList:
    """
    This is a list of datalog rules, which makes up the body of a datalog clause
    ex: Head(a, d) :- A(a, b), B(b, c) C(c, d).
    """

    def __init__(self, rule_sequence, start_term: int):
        self.rules: List[Union[DatalogTrueFact, DatalogRule]] = []
        for term in rule_sequence:
            # If its a string, its a production rule
            if isinstance(term, str):
                if term == TRUE_FACT_NAME:
                    self.rules.append(DatalogTrueFact(chr(start_term)))
                    start_term += 1
                    continue

                self.rules.append(
                    DatalogRule(term, chr(start_term), chr(start_term + 1))
                )
                start_term += 1
            # If its a terminal, we must make sure the name matches that of the fact.
            elif isinstance(term, Terminal):
                for val in term.terminal:
                    self.rules.append(
                        DatalogRule(str(val), chr(start_term), chr(start_term + 1))
                    )
                    start_term += 1
            else:
                print(f"WARNING term is not string/terminal: {term}")
                raise

    @property
    def val(self) -> str:
        return ",".join([x.val for x in self.rules])


class DatalogClause:
    def __init__(self, head: DatalogRule, body: DatalogRuleList):
        self.head = head
        self.body = body
        self.head.end_char = self.body.rules[len(self.body.rules) - 1].end_char

    @property
    def val(self) -> str:
        return f"{self.head.val} :- {self.body.val}."


class DatalogGrammar:
    RULE_START = "a"

    def __init__(self, trace: ProgramTrace):
        self.trace = trace
        self.clause_decls: List[DatalogRuleDecl] = []
        self.output_decls: List[DatalogOutputDecl] = []
        self.clauses: List[DatalogClause] = []
        self.extract_datalog_grammar()

    def extract_datalog_grammar(self):
        unique_rules: Dict[str, bool] = {}
        grammar = trace_to_grammar(self.trace)
        # Note, this is potentially buggy for now.
        # grammar.simplify()
        for prod_name in grammar.productions:
            if prod_name not in unique_rules:
                unique_rules[prod_name] = True
                self.clause_decls.append(DatalogRuleDecl(prod_name))
                # Always output the "<START>" rule.
                if "<START>" in prod_name:
                    self.output_decls.append(DatalogOutputDecl(prod_name))
                # Optional delete this, its useful for debugging
                else:
                    self.output_decls.append(DatalogOutputDecl(prod_name))

            # There might be no rules anyway :)
            if len(grammar.productions[prod_name].rules) == 0:
                self.clauses.append(
                    DatalogClause(
                        DatalogRule(prod_name),
                        DatalogRuleList([TRUE_FACT_NAME], ord(self.RULE_START)),
                    )
                )
                continue
            for rule in grammar.productions[prod_name].rules:
                # Might be an empty tuple
                if len(rule.sequence) == 0:
                    self.clauses.append(
                        DatalogClause(
                            DatalogRule(prod_name),
                            DatalogRuleList([TRUE_FACT_NAME], ord(self.RULE_START)),
                        )
                    )
                else:
                    self.clauses.append(
                        DatalogClause(
                            DatalogRule(prod_name),
                            DatalogRuleList(rule.sequence, ord(self.RULE_START)),
                        )
                    )

    @property
    def val(self) -> str:
        return "\n".join(
            [x.val for x in self.clause_decls]
            + [x.val for x in self.output_decls]
            + [x.val for x in self.clauses]
        )


class ExtractDatalogCommand(CommandExtension[ExtractGrammarCommand]):
    name = "datalog"
    parent_type = ExtractGrammarCommand
    datalog_grammar: DatalogGrammar
    datalog_fact_decls: List[DatalogFactDecl]
    datalog_facts: List[DatalogFact]
    true_fact_decl: DatalogTrueFactDecl
    true_facts: List[DatalogTrueFact]

    def __init_arguments__(self, parser: ArgumentParser):
        parser.add_argument(
            "--extract-datalog",
            "-d",
            type=str,
            default=None,
            help="path to which to optionally save a datalog grammar",
        )

    def run(self, command: ExtractGrammarCommand, args: Namespace):
        if len(command.traces) > 1:
            raise NotImplementedError(
                "TODO: Add support for generating DataLog grammars from multiple traces"
            )
        elif args.extract_datalog is None:
            return 0
        trace = command.traces[0]
        inputs = list(trace.inputs)
        if len(inputs) != 1:
            raise NotImplementedError("TODO: Add support for extracting DataLog grammars from traces with more than "
                                      "one input")
        data = inputs[0].content
        self.datalog_grammar = DatalogGrammar(trace)
        unique_bytes: Dict[int, bool] = {}
        self.datalog_fact_decls = []
        self.datalog_facts = []
        self.true_fact_decl = DatalogTrueFactDecl()
        self.true_facts = []
        for i, byte in enumerate(data):
            # Add another true fact
            self.true_facts.append(DatalogTrueFact(i))
            # Declare the new type of byte
            if byte not in unique_bytes:
                self.datalog_fact_decls.append(DatalogFactDecl(str(byte)))
                unique_bytes[byte] = True
            self.datalog_facts.append(DatalogFact(str(byte), i, i + 1))
        return 0

    def __str__(self):
        facts = "\n".join(
            [self.true_fact_decl.val]
            + [x.val + "." for x in self.true_facts]
            + [x.val for x in self.datalog_fact_decls]
            + [fact.val for fact in self.datalog_facts]
        )
        grammar = self.datalog_grammar.val
        return f"{facts}\n\n{grammar}"
