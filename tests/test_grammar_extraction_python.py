from abc import ABC
from collections import defaultdict
from typing import Dict, Iterable, Iterator, List, Optional, Set, Tuple, Union

import pytest

from polytracker import BasicBlock, ByteOffset, Function, TaintForest, TaintAccess, Taints, TaintOutput
from polytracker.grammars import Grammar, parse_tree_to_grammar
from polytracker.inputs import Input
from polytracker.parsing import NonGeneralizedParseTree, trace_to_non_generalized_tree
from polytracker.tracing import BasicBlockEntry, FunctionEntry, FunctionReturn, ProgramTrace, TraceEvent


class Counter:
    def __init__(self):
        self.n = 0

    def increment(self):
        self.n += 1

    def __int__(self):
        ret = self.n
        self.increment()
        return ret


class BasicBlockMock(BasicBlock):
    def taints(self) -> Taints:
        raise NotImplementedError("TODO: Implement this function when needed")

    def entries(self) -> Iterator["BasicBlockEntry"]:
        raise NotImplementedError("TODO: Implement this function when needed")


class FunctionMock(Function):
    def taints(self) -> Taints:
        raise NotImplementedError("TODO: Implement this function when needed")

    def calls_to(self) -> Set["Function"]:
        raise NotImplementedError("TODO: Implement this function when needed")

    def called_from(self) -> Set["Function"]:
        raise NotImplementedError("TODO: Implement this function when needed")


class TracedEvent(ABC, TraceEvent):
    def __init__(self, tracer: "Tracer"):
        super().__init__(len(tracer.events))
        tracer.events[self.uid] = self
        self.tracer: Tracer = tracer
        entry = tracer.call_stack[-1]
        f_name = entry.function.name
        self._function: Function = tracer.functions_by_name[f_name]
        self._function_entry: TracedFunctionEntry = entry

    @property
    def function(self) -> Function:
        return self._function

    @property
    def previous_event(self) -> Optional["TraceEvent"]:
        if self.uid == 0:
            return None
        return self.tracer.events[self.uid - 1]

    @property
    def next_event(self) -> Optional["TraceEvent"]:
        if self.uid >= len(self.tracer.events) - 1:
            return None
        return self.tracer.events[self.uid + 1]

    @property
    def next_global_event(self) -> Optional["TraceEvent"]:
        return self.next_event

    @property
    def previous_global_event(self) -> Optional["TraceEvent"]:
        return self.previous_event

    @property
    def function_entry(self) -> Optional["TracedFunctionEntry"]:
        return self._function_entry


class TracedBasicBlockEntry(TracedEvent, BasicBlockEntry):
    def __init__(self, tracer: "Tracer", bb_name: str):
        super().__init__(tracer)
        self.name: str = bb_name
        self.consumed: List[int] = []
        tracer.bb_stack[-1].append(self)
        f_name = self.function.name
        bbs = tracer.bbs[f_name]
        if bb_name not in bbs:
            bbs[bb_name] = BasicBlockMock(self.function, len(bbs))
        self._basic_block: BasicBlock = bbs[bb_name]

    @property
    def basic_block(self) -> BasicBlock:
        return self._basic_block

    def taints(self) -> Taints:
        return Taints((ByteOffset(source=self.tracer.source, offset=i) for i in self.consumed))


class TracedFunctionEntry(TracedEvent, FunctionEntry):
    def __init__(self, tracer: "Tracer", func_name: str):
        if func_name not in tracer.functions_by_name:
            func: Function = FunctionMock(func_name, len(tracer.functions_by_name))
            tracer.functions_by_name[func_name] = func
        else:
            func = tracer.functions_by_name[func_name]
        self._function: Function = func
        tracer.call_stack.append(self)
        super().__init__(tracer)
        self.name: str = func_name
        self._function_return: Optional[FunctionReturn] = None
        tracer.bb_stack.append([])

    @property
    def function_return(self) -> Optional[FunctionReturn]:
        return self._function_return

    @function_return.setter
    def function_return(self, new_value: FunctionReturn):
        if self._function_return is not None and new_value is not self._function_return:
            raise ValueError(f"{self!r} is already set to return to {self._function_return!r}, not {new_value!r}")
        self._function_return = new_value

    def taints(self) -> Taints:
        return Taints(())


class TracedFunctionReturn(TracedEvent, FunctionReturn):
    def __init__(self, tracer: "Tracer"):
        super().__init__(tracer)
        self._basic_block: BasicBlock = tracer.current_bb.basic_block

    @property
    def basic_block(self) -> BasicBlock:
        return self._basic_block

    def taints(self) -> Taints:
        return Taints(())


class Tracer(ProgramTrace):
    def __init__(self, inputstr: bytes):
        self.source: Input = Input(uid=1, path="test.data", size=len(inputstr), content=inputstr)
        self.call_stack: List[TracedFunctionEntry] = []
        self.bb_stack: List[List[TracedBasicBlockEntry]] = []
        self.events: Dict[int, TraceEvent] = {}
        self.functions_by_name: Dict[str, Function] = {}
        self.bbs: Dict[str, Dict[str, BasicBlock]] = defaultdict(dict)
        self.inputstr: bytes = inputstr
        self.input_offset: int = 0

    def __len__(self) -> int:
        return len(self.events)

    def __iter__(self) -> Iterator[TraceEvent]:
        return iter(self.events.values())

    @property
    def functions(self) -> Iterable[Function]:
        return self.functions_by_name.values()

    @property
    def basic_blocks(self) -> Iterable[BasicBlock]:
        bbs: List[BasicBlock] = []
        for blocks in self.bbs.values():
            bbs.extend(blocks.values())
        return bbs

    def has_event(self, uid: int) -> bool:
        return uid in self.events

    def get_event(self, uid: int) -> TraceEvent:
        return self.events[uid]

    def get_function(self, name: str) -> Function:
        return self.functions_by_name[name]

    def has_function(self, name: str) -> bool:
        return name in self.functions_by_name

    def access_sequence(self) -> Iterator[TaintAccess]:
        raise NotImplementedError("TODO: Implement this later if we need it")

    @property
    def num_accesses(self) -> int:
        return sum(len(bb.consumed) for bb in self.events if isinstance(bb, TracedBasicBlockEntry))

    @property
    def inputs(self) -> Iterable[Input]:
        return (self.source,)

    @property
    def taint_forest(self) -> TaintForest:
        raise NotImplementedError()

    def file_offset(self, node) -> ByteOffset:
        raise NotImplementedError()

    def __getitem__(self, uid: int) -> TraceEvent:
        return self.events[uid]

    def __contains__(self, uid: int):
        return uid in self.events

    @property
    def last_event(self) -> Optional[TraceEvent]:
        if self.events:
            return self.events[-1]
        else:
            return None

    @property
    def current_bb(self) -> TracedBasicBlockEntry:
        return self.bb_stack[-1][-1]

    @property
    def current_bb_name(self) -> str:
        return self.bb_stack[-1][-1].name

    def peek(self, num_bytes: int) -> bytes:
        bytes_read = self.inputstr[self.input_offset: self.input_offset + num_bytes]
        self.current_bb.consumed.extend(range(self.input_offset, self.input_offset + len(bytes_read)))
        return bytes_read

    def read(self, num_bytes: int) -> bytes:
        bytes_read = self.peek(num_bytes)
        self.input_offset += len(bytes_read)
        return bytes_read

    def seek(self, input_offset: int):
        self.input_offset = input_offset

    def function_call(self, name: str) -> TracedFunctionEntry:
        return TracedFunctionEntry(self, name)

    def function_return(self, name) -> FunctionReturn:
        f = TracedFunctionReturn(self)
        if self.call_stack:
            self.call_stack[-1].function_return = f
            self.call_stack.pop()
            self.bb_stack[-1].pop()
            if self.call_stack:
                self.bb_entry(f"{self.current_bb_name}_after_call_to_{name}")
        return f

    def bb_entry(self, name: str) -> TracedBasicBlockEntry:
        return TracedBasicBlockEntry(self, name)

    @property
    def outputs(self) -> Optional[Iterable[Input]]:
        raise NotImplementedError()

    @property
    def output_taints(self) -> Iterable[TaintOutput]:
        raise NotImplementedError()


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
    assert first_byte == b'"'
    ret = bytearray()
    while True:
        tracer.bb_entry("while_in_string")
        next_byte = tracer.read(1)
        if len(next_byte) == 0:
            raise ValueError()
        elif next_byte == b'"':
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
        if len(next_byte) == 0 or next_byte[0] < ord("0") or next_byte[0] > ord("9"):
            tracer.bb_entry("int_finished")
            break
        tracer.bb_entry("int_not_finished")
        number.extend(next_byte)
        tracer.input_offset += 1
    return int(number.decode("utf-8"))


@traced
def parse_terminal(tracer: Tracer) -> Union[int, str]:
    next_byte = tracer.peek(1)
    if next_byte == b'"':
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


def make_trace(inputstr: bytes) -> Tuple[List[Union[int, str]], Tracer]:
    tracer = Tracer(inputstr)
    result = parse_parens(tracer)
    return result, tracer


class GrammarTestCase:
    def __init__(self, input_string: bytes, trace: Tracer):
        self.input_string: bytes = input_string
        self.trace: Tracer = trace
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
    input_str = b'(1, 2, ("foo", 5, "bar"), 3, 4)'
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
    # print(simple_grammar.grammar)
    m = simple_grammar.grammar.match(simple_grammar.input_string)
    assert bool(m)
    # print(m.parse_tree.to_dag().to_dot(labeler=lambda t: repr(str(t.value))))


def test_grammar_simplification(simple_grammar: GrammarTestCase):
    # print(simple_grammar.simplified_grammar)
    m = simple_grammar.simplified_grammar.match(simple_grammar.input_string)
    assert bool(m)
    # print(m.parse_tree.to_dag().to_dot(labeler=lambda t: repr(str(t.value))))
