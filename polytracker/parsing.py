from typing import Dict, Generic, Iterator, List, Optional, Tuple, Type, TypeVar, Union

from intervaltree import Interval, IntervalTree
from tqdm import tqdm

from .tracing import BasicBlockEntry, FunctionCall, FunctionReturn, PolyTrackerTrace, TraceEvent


T = TypeVar("T", bound="ParseTree")
V = TypeVar("V")


class ParseTree(Generic[V]):
    def __init__(self: T, value: V):
        self.value: V = value
        self.children: List[T] = []
        self._descendants: Optional[int] = None

    @property
    def descendants(self) -> int:
        if self._descendants is None:
            for n in self.postorder_traversal():
                n._descendants = sum(c._descendants for c in n.children) + len(n)
        return self._descendants

    def postorder_traversal(self: T) -> Iterator[T]:
        s: List[Tuple[bool, T]] = [(False, self)]
        while s:
            expanded_children, node = s.pop()
            if not expanded_children and node.children:
                s.append((True, node))
                s.extend((False, child) for child in reversed(node.children))
            else:
                # all of node's children have been expanded
                yield node

    def preorder_traversal(self: T) -> Iterator[T]:
        s: List[T] = [self]
        while s:
            node = s.pop()
            yield node
            s.extend(reversed(node.children))

    def clone(self: T) -> T:
        ret = self.__class__(self.value)
        ret.children = [c.clone() for c in self.children]
        return ret

    def is_leaf(self) -> bool:
        return not bool(self.children)

    def __iter__(self) -> Iterator["ParseTree"]:
        return iter(self.children)

    def __len__(self):
        return len(self.children)

    def __str__(self):
        ret = ""
        stack = [self]
        while stack:
            n = stack.pop()
            if isinstance(n, str):
                ret = f"{ret}{n}"
                continue
            value_name = str(n.value)
            if not n.children:
                ret = f"{ret}{value_name}"
            else:
                if value_name:
                    ret = f"{ret}{value_name} ["
                    stack.append("]")
                for i, c in reversed(list(enumerate(n.children))):
                    if i > 0:
                        stack.append(" ")
                    stack.append(c)
        return ret


def escape_byte(byte_value: int) -> str:
    if byte_value == ord("\n"):
        b = "\\n"
    elif byte_value == ord("\t"):
        b = "\\t"
    elif byte_value == ord("\r"):
        b = "\\r"
    elif byte_value == ord('"'):
        b = '\\"'
    elif byte_value == ord("\\"):
        b = "\\\\"
    elif ord(" ") <= byte_value <= ord("~"):
        b = chr(byte_value)
    else:
        b = f"\\x{byte_value:02x}"
    return b


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
            ret = f"{ret}{escape_byte(i)}"
        return f'{ret}"'


class Start:
    def __str__(self):
        return "<START>"


N = TypeVar('N', bound=ParseTree[Union[Start, TraceEvent, Terminal]])


def trace_to_tree(
        trace: PolyTrackerTrace,
        node_type: Type[N] = ParseTree[Union[Start, TraceEvent, Terminal]],
        include_terminals: bool = True
) -> N:
    if trace.entrypoint is None:
        raise ValueError(f"Trace {trace} does not have an entrypoint!")

    root = node_type(Start())

    nodes_by_event: Dict[TraceEvent, node_type] = {}

    for event in tqdm(trace, unit=" events", leave=False, desc="extracting a parse tree"):
        if isinstance(event, BasicBlockEntry):
            node = node_type(event)
            nodes_by_event[event] = node
            prev_event = event.previous
            parent = None
            if prev_event is not None:
                if isinstance(prev_event, FunctionReturn):
                    if prev_event.function_call is not None:
                        parent = nodes_by_event[prev_event.function_call]
                else:
                    parent = nodes_by_event[prev_event]
            if parent is None:
                parent = root
            parent.children.append(node)
            if include_terminals:
                for token in event.last_consumed_tokens:
                    node.children.append(node_type(Terminal(token)))
        elif isinstance(event, FunctionCall):
            node = node_type(event)
            nodes_by_event[event] = node
            try:
                if event.caller is not None:
                    parent = nodes_by_event[event.caller]
                else:
                    parent = root
            except TypeError:
                # This will be raised by event.caller if the caller cannot be determined
                # (e.g., if this is the first function in the trace)
                parent = root
            parent.children.append(node)

    return root


class NonGeneralizedParseTree(ParseTree[Union[Start, TraceEvent, Terminal]]):
    def __init__(self, value: Union[Start, TraceEvent, Terminal]):
        super().__init__(value)
        self.consumed: List[Tuple[int, int]]
        if isinstance(value, BasicBlockEntry):
            self.intervals: IntervalTree = IntervalTree(self._consumed_intervals())
        else:
            self.intervals = IntervalTree()

    @property
    def begin_offset(self) -> int:
        return self.intervals.begin()

    @property
    def begin_uid(self) -> int:
        if not self.intervals:
            return -1
        return max(i.data for i in self.intervals[self.begin_offset])

    @property
    def end_offset(self) -> int:
        return self.intervals.end()

    @property
    def end_uid(self) -> int:
        if not self.intervals:
            return -1
        return max(i.data for i in self.intervals[self.end_offset - 1])

    def deconflict(self, right_sibling: 'NonGeneralizedParseTree'):
        if self.end_offset <= right_sibling.begin_offset:
            # we do not have overlap
            return
        # record all of our last-used times in the overlap
        our_last_used = []
        their_last_used = []
        for i in range(right_sibling.begin_offset, self.end_offset + 1):
            our_intervals = self.intervals[i]
            if our_intervals:
                assert len(our_intervals) == 1
                our_last_used.append(next(iter(our_intervals)).data)
            else:
                our_last_used.append(-1)
            their_intervals = right_sibling.intervals[i]
            if their_intervals:
                assert len(their_intervals) == 1
                their_last_used.append(next(iter(their_intervals)).data)
            else:
                their_last_used.append(-1)
        winners = [our_last - their_last for our_last, their_last in zip(our_last_used, their_last_used)]
        # TODO: See if we can improve this algorithm
        best_point = self.end_offset
        best_badness = None
        for point in range(0, len(winners) + 1):
            # find the optimal overlap point to partition our intervals
            badness = 0
            for i, winner in enumerate(winners):
                if (i < point and winner < 0) or (i >= point and winner > 0):
                    badness += 1
            if best_badness is None or badness < best_badness:
                best_point = point
                best_badness = badness
        right_sibling.intervals.chop(0, right_sibling.begin_offset + best_point)
        self.intervals.chop(right_sibling.begin_offset + best_point, self.end_offset)

    def bottom_up_pass(self):
        # ensure that none of our children's intervals overlap
        for child, right_sibling in zip(self.children, self.children[1:]):
            child.deconflict(right_sibling)
        for child in self.children:
            # update our intervals based off of the child
            if not self.intervals:
                self.intervals |= child.intervals
                continue
            for interval in child.intervals:
                existing = self.intervals[interval.begin:interval.end]
                if existing:
                    best = max(i.data for i in existing)
                    if interval.data > best:
                        self.intervals.chop(interval.begin, interval.end)
                        self.intervals.addi(interval.begin, interval.end, interval.data)
                else:
                    self.intervals.addi(interval.begin, interval.end, interval.data)

    def top_down_pass(self):
        begin = self.begin_offset
        end = self.end_offset
        if end <= begin:
            self.children = []
            # assert not self.children or all(c.end_offset <= c.begin_offset for c in self.children)
        else:
            self.intervals = IntervalTree()
            self.intervals.addi(begin, end)
            for child in self.children:
                # make sure all of our children are within our own interval
                child.intervals.chop(0, begin)
                if child.end_offset > end:
                    child.intervals.chop(end, child.end_offset)
                self.intervals.chop(child.begin_offset, child.end_offset)

    def _consumed_intervals(self) -> Iterator[Interval]:
        if not isinstance(self.value, BasicBlockEntry):
            return
        start_offset: Optional[int] = None
        last_offset: Optional[int] = None
        for offset in sorted(self.value.consumed):
            if start_offset is None:
                start_offset = last_offset = offset
            elif start_offset + 1 != offset:
                # this is not a contiguous byte sequence
                # so yield the previous token
                yield Interval(start_offset, last_offset + 1, self.value.uid)
                start_offset = last_offset = offset
            else:
                # this is a contiguous byte sequence, so update its end
                last_offset = offset
        if start_offset is not None:
            yield Interval(start_offset, last_offset + 1, self.value.uid)


def trace_to_non_generalized_tree(trace: PolyTrackerTrace) -> NonGeneralizedParseTree:
    tree = trace_to_tree(trace, NonGeneralizedParseTree, False)

    for node in tqdm(
            tree.postorder_traversal(),
            total=tree.descendants + 1,
            leave=False,
            desc=" deconflicting parse tree ranges",
            unit=" nodes"
    ):
        if isinstance(node.value, Start):
            node.intervals[0:len(trace.inputstr)] = 0
        node.bottom_up_pass()

    for node in tqdm(
            tree.preorder_traversal(),
            total=tree.descendants + 1,
            leave=False,
            desc=" finalizing parse tree ranges",
            unit=" nodes"
    ):
        node_begin = node.begin_offset
        node_end = node.end_offset
        node.top_down_pass()
        # add terminals
        last_end = node_begin
        new_children: List[NonGeneralizedParseTree] = []
        for child in node.children:
            if child.begin_offset >= child.end_offset:
                continue
            if last_end < child.begin_offset:
                new_children.append(NonGeneralizedParseTree(Terminal(trace.inputstr[last_end:child.begin_offset])))
                if new_children[-1].value.terminal == b"{\n\t\"foo\": [1, 2, 3, 4],\n\t\"bar\": \"testin":
                    breakpoint()
            new_children.append(child)
            last_end = child.end_offset
        if last_end < node_end:
            new_children.append(NonGeneralizedParseTree(Terminal(trace.inputstr[last_end:node_end])))
        node.children = new_children

    for node in tree.preorder_traversal():
        print(node.value)

    return tree
