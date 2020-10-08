from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple, Type, TypeVar, Union

import pytest

from polytracker.grammars import Completion, EarleyParser, Grammar, parse_tree_to_grammar, Prediction
from polytracker.parsing import NonGeneralizedParseTree, trace_to_non_generalized_tree
from polytracker.tracing import BasicBlockEntry, FunctionCall, FunctionReturn, PolyTrackerTrace, TraceEvent


class Counter:
    def __init__(self):
        self.n = 0

    def increment(self):
        self.n += 1

    def __int__(self):
        ret = self.n
        self.increment()
        return ret


E = TypeVar("E", bound=TraceEvent)


class Tracer:
    def __init__(self, inputstr: bytes):
        self.call_stack: List[FunctionCall] = []
        self.bb_stack: List[List[Tuple[str, BasicBlockEntry]]] = []
        self.events: List[TraceEvent] = []
        self.functions: Dict[str, int] = {}
        self.bbs: Dict[str, Dict[str, int]] = defaultdict(dict)
        self.inputstr: bytes = inputstr
        self.input_offset: int = 0

    @property
    def last_event(self) -> Optional[TraceEvent]:
        if self.events:
            return self.events[-1]
        else:
            return None

    @property
    def current_bb(self) -> BasicBlockEntry:
        return self.bb_stack[-1][-1][1]

    @property
    def current_bb_name(self) -> str:
        return self.bb_stack[-1][-1][0]

    def peek(self, num_bytes: int) -> bytes:
        bytes_read = self.inputstr[self.input_offset:self.input_offset + num_bytes]
        self.current_bb.consumed.extend(range(self.input_offset, self.input_offset + len(bytes_read)))
        return bytes_read

    def read(self, num_bytes: int) -> bytes:
        bytes_read = self.peek(num_bytes)
        self.input_offset += len(bytes_read)
        return bytes_read

    def seek(self, input_offset: int):
        self.input_offset = input_offset

    def emplace(self, event_type: Type[E], **kwargs) -> E:
        uid = len(self.events)
        if uid > 0:
            event = event_type(uid=uid, previous_uid=uid - 1, **kwargs)
            self.events[uid - 1].next_uid = uid
        else:
            event: E = event_type(uid=uid, **kwargs)
        self.events.append(event)
        return event

    def function_call(self, name: str) -> FunctionCall:
        c = self.emplace(FunctionCall, name=name)
        if name not in self.functions:
            self.functions[name] = len(self.functions)
        self.call_stack.append(c)
        self.bb_stack.append([])
        return c

    def _call_event_uid(self) -> Optional[int]:
        if not self.call_stack:
            return None
        else:
            return self.call_stack[-1].uid

    def _returning_to_uid(self) -> Optional[int]:
        if not self.call_stack or self.call_stack[-1].previous_uid is None:
            return None
        else:
            return self.call_stack[-1].previous_uid

    def function_return(self, name) -> FunctionReturn:
        f = self.emplace(
            FunctionReturn,
            name=name,
            call_event_uid=self._call_event_uid(),
            returning_to_uid=self._returning_to_uid()
        )
        if self.call_stack:
            self.call_stack[-1].return_uid = f.uid
            self.call_stack.pop()
            self.bb_stack[-1].pop()
            if self.call_stack:
                self.bb_entry(f"{self.current_bb_name}_after_call_to_{name}")
        return f

    def bb_entry(self, name: str) -> BasicBlockEntry:
        f_name = self.call_stack[-1].name
        f_index = self.functions[f_name]
        bbs = self.bbs[f_name]
        if name not in bbs:
            bbs[name] = len(bbs)
        bb_index = bbs[name]
        entry_count = sum(1 for _, bb in self.bb_stack[-1] if bb_index == bb.bb_index) + 1
        bb = self.emplace(
            BasicBlockEntry,
            function_index=f_index,
            bb_index=bb_index,
            entry_count=entry_count,
            global_index=(f_index << 32) | bb_index,
            function_call_uid=self.call_stack[-1].uid
        )
        self.bb_stack[-1].append((name, bb))
        return bb

    def to_trace(self) -> PolyTrackerTrace:
        return PolyTrackerTrace(self.events, inputstr=self.inputstr)


def traced(func):
    def wrapped(tracer: Tracer, *args, **kwargs):
        tracer.function_call(func.__name__)
        tracer.bb_entry("entry")
        ret = func(tracer, *args, **kwargs)
        tracer.function_return(func.__name__)
        return ret
    return wrapped


@traced
def skip_whitespace(tracer: Tracer):
    while True:
        tracer.bb_entry("while_whitespace")
        next_byte = tracer.peek(1)
        if next_byte == b" " or next_byte == b"\t" or next_byte == "\n":
            tracer.bb_entry("is_whitespace")
            tracer.input_offset += 1
        else:
            tracer.bb_entry("not_whitespace")
            break


@traced
def parse_string(tracer: Tracer) -> str:
    first_byte = tracer.read(1)
    assert first_byte == b"\""
    ret = bytearray()
    while True:
        tracer.bb_entry("while_in_string")
        next_byte = tracer.read(1)
        if len(next_byte) == 0:
            raise ValueError()
        elif next_byte == b"\"":
            tracer.bb_entry("string_finished")
            break
        tracer.bb_entry("string_not_finished")
        ret.extend(next_byte)
    return ret.decode("utf-8")


@traced
def parse_int(tracer: Tracer) -> int:
    number = bytearray()
    while True:
        tracer.bb_entry("while_in_int")
        next_byte = tracer.peek(1)
        if len(next_byte) == 0 or next_byte[0] < ord('0') or next_byte[0] > ord('9'):
            tracer.bb_entry("int_finished")
            break
        tracer.bb_entry("int_not_finished")
        number.extend(next_byte)
        tracer.input_offset += 1
    return int(number.decode("utf-8"))


@traced
def parse_terminal(tracer: Tracer) -> Union[int, str]:
    next_byte = tracer.peek(1)
    if next_byte == b"\"":
        tracer.bb_entry("terminal_is_string")
        return parse_string(tracer)
    else:
        tracer.bb_entry("terminal_is_int")
        return parse_int(tracer)


@traced
def parse_list(tracer: Tracer) -> List[Union[int, str]]:
    ret = []
    while True:
        tracer.bb_entry("while_list_item")
        skip_whitespace(tracer)
        first_byte = tracer.peek(1)
        if first_byte == b"(":
            tracer.bb_entry("found_paren")
            ret.append(parse_parens(tracer))
        elif first_byte == b")":
            tracer.bb_entry("found_close_paren")
            break
        else:
            tracer.bb_entry("no_paren")
            ret.append(parse_terminal(tracer))
        skip_whitespace(tracer)
        if tracer.peek(1) != b",":
            tracer.bb_entry("no_comma")
            break
        tracer.bb_entry("found_comma")
        tracer.input_offset += 1
    return ret


@traced
def parse_parens(tracer: Tracer) -> List[Union[int, str]]:
    skip_whitespace(tracer)
    b = tracer.read(1)
    assert b == b"("
    ret = parse_list(tracer)
    b = tracer.read(1)
    assert b == b")"
    return ret


def make_trace(inputstr: bytes) -> Tuple[List[Union[int, str]], PolyTrackerTrace]:
    tracer = Tracer(inputstr)
    result = parse_parens(tracer)
    return result, tracer.to_trace()


class GrammarTestCase:
    def __init__(self, input_string: bytes, trace: PolyTrackerTrace):
        self.input_string: bytes = input_string
        self.trace: PolyTrackerTrace = trace
        self._tree: Optional[NonGeneralizedParseTree] = None
        self._grammar: Optional[Grammar] = None
        self._simplified_grammar: Optional[Grammar] = None

    @property
    def tree(self) -> NonGeneralizedParseTree:
        if self._tree is None:
            self._tree = trace_to_non_generalized_tree(self.trace)
        return self._tree

    @property
    def grammar(self) -> Grammar:
        if self._grammar is None:
            self._grammar = parse_tree_to_grammar(self.tree)
        return self._grammar

    @property
    def simplified_grammar(self) -> Grammar:
        if self._simplified_grammar is None:
            self._simplified_grammar = parse_tree_to_grammar(self.tree)
            self._simplified_grammar.simplify()
        return self._simplified_grammar


@pytest.fixture
def simple_grammar() -> GrammarTestCase:
    input_str = b"(1, 2, (\"foo\", 5, \"bar\"), 3, 4)"
    result, trace = make_trace(input_str)
    assert result == [1, 2, ["foo", 5, "bar"], 3, 4]
    return GrammarTestCase(input_str, trace)


def test_parse_tree_generation(simple_grammar: GrammarTestCase):
    """Tests the generation of a non-generalized parse tree from a program trace"""
    assert simple_grammar.tree.matches() == simple_grammar.trace.inputstr
    # print(simple_grammar.tree.to_dag().to_dot(labeler=lambda n: repr(str(n.value))))


def test_parse_tree_simplification(simple_grammar: GrammarTestCase):
    """Tests the generation of a non-generalized parse tree from a program trace"""
    tree = simple_grammar.tree.clone()
    tree.simplify()
    assert tree.matches() == simple_grammar.trace.inputstr


def test_grammar_extraction(simple_grammar: GrammarTestCase):
    simple_grammar.grammar.verify(True)


def test_grammar_matching(simple_grammar: GrammarTestCase):
    print(simple_grammar.grammar)
    m = simple_grammar.grammar.match(simple_grammar.input_string)
    assert bool(m)
    print(m.parse_tree.to_dag().to_dot(labeler=lambda t: repr(str(t.value))))


def test_grammar_simplification(simple_grammar: GrammarTestCase):
    print(simple_grammar.simplified_grammar)
    m = simple_grammar.simplified_grammar.match(simple_grammar.input_string)
    assert bool(m)
    print(m.parse_tree.to_dag().to_dot(labeler=lambda t: repr(str(t.value))))
