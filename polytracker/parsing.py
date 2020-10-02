from abc import ABC, abstractmethod
from typing import Dict, Generic, Iterable, Iterator, List, Optional, Tuple, Type, TypeVar, Union

from intervaltree import Interval, IntervalTree
from tqdm import tqdm

from .cfg import DAG
from .tracing import BasicBlockEntry, FunctionCall, FunctionReturn, PolyTrackerTrace, TraceEvent


V = TypeVar("V")
T = TypeVar("T", bound="ParseTree")


class ParseTree(ABC, Generic[V]):
    __slots__ = "value", "_descendants"

    def __init__(self: T, value: V):
        self.value: V = value
        self._descendants: Optional[int] = None

    @property
    @abstractmethod
    def children(self) -> List[T]:
        raise NotImplementedError()

    def to_dag(self) -> DAG["ParseTree[V]"]:
        dag: DAG[ParseTree[V]] = DAG()
        if self.children:
            dag.add_edges_from((node, child) for node in self.preorder_traversal() for child in node.children)
        else:
            dag.add_node(self)
        return dag

    @property
    def descendants(self) -> int:
        if self._descendants is None:
            for n in self.postorder_traversal():
                n._descendants = sum(c._descendants for c in n.children) + len(n)  # type: ignore
        return self._descendants  # type: ignore

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

    @abstractmethod
    def clone(self: T) -> T:
        raise NotImplementedError()

    def is_leaf(self) -> bool:
        return not bool(self.children)

    def leaves(self) -> Iterator[T]:
        for t in self.preorder_traversal():
            if t.is_leaf():
                yield t  # type: ignore

    def __getitem__(self, child_index: int) -> V:
        return self.children[child_index]

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


class ImmutableParseTree(Generic[V], ParseTree[V]):
    __slots__ = "_children"

    def __init__(self, value: V, children: Iterable[V] = ()):
        super().__init__(value)
        self._children: List[V] = list(children)

    @property
    def children(self) -> List[V]:
        return self._children

    def clone(self: T) -> T:
        ret = self.__class__(self.value)
        ret.children = [c.clone() for c in self.children]
        return ret


class MutableParseTree(Generic[V], ImmutableParseTree[V]):
    @ImmutableParseTree.children.setter
    def children(self, new_children: List[V]):
        self._children = new_children

    def add_child(self, new_child: V):
        self._children.append(new_child)

    def __setitem__(self, child_index: int, new_child: V):
        self.children[child_index] = new_child


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


def highlight_offset(text: bytes, offset, highlight_length=20) -> str:
    length_div_2 = highlight_length // 2
    start_offset = max(offset - length_div_2, 0)
    end_offset = min(offset + length_div_2, len(text))
    before = 0
    offset_len = 1
    ret = ""
    for i, b in enumerate(text[start_offset:end_offset]):
        byte_text = escape_byte(b)
        if i < offset - start_offset:
            before += len(byte_text)
        elif i == offset - start_offset:
            offset_len = len(byte_text)
        ret = f"{ret}{byte_text}"
    ret = f"\"{ret}\"\n {' ' * before}{'^' * offset_len}"
    return ret


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


N = TypeVar("N", bound=ParseTree[Union[Start, TraceEvent, Terminal]])


def trace_to_tree(
    trace: PolyTrackerTrace, node_type: Type[N] = ParseTree[Union[Start, TraceEvent, Terminal]], include_terminals: bool = True  # type: ignore
) -> N:
    if trace.entrypoint is None:
        raise ValueError(f"Trace {trace} does not have an entrypoint!")

    root = node_type(Start())

    nodes_by_event: Dict[TraceEvent, N] = {}

    for event in tqdm(trace, unit=" events", leave=False, desc="extracting a parse tree"):
        if isinstance(event, BasicBlockEntry):
            node: N = node_type(event)
            nodes_by_event[event] = node
            prev_event = event.previous
            parent = None
            if prev_event is not None:
                if isinstance(prev_event, FunctionReturn):
                    if prev_event.function_call is not None and prev_event.function_call.caller is not None:
                        parent = nodes_by_event[prev_event.function_call.caller]
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


class NonGeneralizedParseTree(MutableParseTree[Union[Start, TraceEvent, Terminal]]):
    def __init__(self, value: Union[Start, TraceEvent, Terminal]):
        super().__init__(value)
        self.consumed: List[Tuple[int, int]]
        if isinstance(value, BasicBlockEntry):
            self.intervals: IntervalTree = IntervalTree(self._consumed_intervals())
        else:
            self.intervals = IntervalTree()
        self._begin: Optional[int] = None
        self._end: Optional[int] = None

    @property
    def begin_offset(self) -> int:
        if self._begin is not None:
            return self._begin
        return self.intervals.begin()

    @property
    def end_offset(self) -> int:
        if self._end is not None:
            return self._end
        return self.intervals.end()

    def terminals(self) -> Iterator[Terminal]:
        for leaf in self.leaves():  # type: ignore
            assert isinstance(leaf.value, Terminal)
            yield leaf.value

    def matches(self) -> bytes:
        return b"".join(terminal.terminal for terminal in self.terminals())

    def verify_bounds(self, check_overlap=True, check_coverage=True, check_missing_children=True):
        covered_input_bytes = IntervalTree()
        for child in self.children:
            if check_overlap and covered_input_bytes.overlaps(child.begin_offset, child.end_offset):
                overlap = ", ".join([interval.data for interval in covered_input_bytes[child.begin_offset : child.end_offset]])
                raise ValueError(f"Child node {child.value!s} of {self.value!s} overlaps with these siblings: " f"{overlap!r}")
            if child.end_offset > child.begin_offset:
                covered_input_bytes.addi(child.begin_offset, child.end_offset, str(child.value))
        if (
            check_coverage
            and not self.is_leaf()
            and (covered_input_bytes.begin() != self.begin_offset or covered_input_bytes.end() != self.end_offset)
        ):
            raise ValueError(
                f"Node {self.value!s} was expected to have bounds ({self.begin_offset}, "
                f"{self.end_offset}), but its children only covered bounds "
                f"({covered_input_bytes.begin()}, {covered_input_bytes.end()})"
            )
        if check_missing_children and not self.is_leaf():
            covered_input_bytes.merge_overlaps(strict=False)
            if len(covered_input_bytes) > 1:
                missing = IntervalTree.from_tuples([(self.begin_offset, self.end_offset)]) - covered_input_bytes
                missing_str = ", ".join(f"[{i.begin}:{i.end}]" for i in missing)
                raise ValueError(f"Node {self.value!s} is missing children that cover these byte ranges: {missing_str}")

    def verify(self, string: bytes):
        offset: int = 0
        remaining: bytes = string
        last_non_terminal: str = "<START>"
        for node in self.preorder_traversal():
            # first, make sure none of our children overlap and that our entire range is covered
            node.verify_bounds()
            if not isinstance(node.value, Terminal):
                last_non_terminal = str(node.value)
                continue
            terminal = node.value
            if not remaining.startswith(terminal.terminal):
                raise ValueError(
                    f"Expected byte sequence {terminal!s} at byte offset {offset} produced by production "
                    f"{last_non_terminal}, but instead found:\n"
                    f"{highlight_offset(text=string, offset=offset)}"
                )
            terminal_length = len(terminal.terminal)
            remaining = remaining[terminal_length:]
            offset += terminal_length

    def simplify(self):
        for node in tqdm(self.postorder_traversal(), leave=False, desc="simplifying parse tree", unit=" nodes"):
            if len(node.children) == 1:
                child = node.children[0]
                if isinstance(child.value, BasicBlockEntry) and len(child.children) == 1:
                    node.children = [child.children[0]]

    def _winners(self, to_compare: "NonGeneralizedParseTree") -> Optional[List[int]]:
        if self.end_offset <= to_compare.begin_offset:
            # we do not have overlap
            return None
        # record all of our last-used times in the overlap
        our_last_used = []
        their_last_used = []
        for i in range(to_compare.begin_offset, self.end_offset + 1):
            our_intervals = self.intervals[i]
            if our_intervals:
                assert len(our_intervals) == 1
                last_used = next(iter(our_intervals)).data
                if last_used is None:
                    last_used = -1
                our_last_used.append(last_used)
            else:
                our_last_used.append(-1)
            their_intervals = to_compare.intervals[i]
            if their_intervals:
                assert len(their_intervals) == 1
                last_used = next(iter(their_intervals)).data
                if last_used is None:
                    last_used = -1
                their_last_used.append(last_used)
            else:
                their_last_used.append(-1)
        return [our_last - their_last for our_last, their_last in zip(our_last_used, their_last_used)]

    def best_partition(self, right_sibling: "NonGeneralizedParseTree") -> Optional[int]:
        winners = self._winners(right_sibling)
        if winners is None:
            # we do not overlap
            return None
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
        return best_point

    def best_subset(self, parent: "NonGeneralizedParseTree") -> Tuple[int, int]:
        winners = self._winners(parent)
        if winners is None:
            raise ValueError("The child does not overlap with its parent! This should never happen.")
        # TODO: See if we can improve this algorithm
        left_offset = 0
        right_offset = len(winners)
        while winners[left_offset] < 0 and left_offset < right_offset:
            left_offset += 1
        while left_offset < right_offset and winners[right_offset - 1] < 0:
            right_offset -= 1
        return left_offset, right_offset

    def deconflict_sibling(self, right_sibling: "NonGeneralizedParseTree"):
        best_point = self.best_partition(right_sibling)
        if best_point is not None:
            self.intervals.chop(right_sibling.begin_offset + best_point, self.end_offset)
            right_sibling.intervals.chop(0, right_sibling.begin_offset + best_point)

    def deconflict_parent(self, parent: "NonGeneralizedParseTree"):
        left_offset, right_offset = self.best_subset(parent)
        self.intervals.chop(self.begin_offset + left_offset, self.end_offset - right_offset)

    def bottom_up_pass(self):
        # first, remove any children that do not produce a terminal
        self.children = [child for child in self.children if child.begin_offset < child.end_offset]
        # ensure that none of our children's intervals overlap
        for child, right_sibling in zip(self.children, self.children[1:]):
            child.deconflict_sibling(right_sibling)
        for child in self.children:
            # update our intervals based off of the child
            self.intervals |= child.intervals
        self.intervals.split_overlaps()
        self.intervals.merge_overlaps(data_reducer=max)
        if __debug__:
            self.verify_bounds(check_overlap=True, check_coverage=False, check_missing_children=False)

    def top_down_pass(self):
        self._begin = self.begin_offset
        self._end = self.end_offset
        if self._end <= self._begin:
            self.children = []
        else:
            self.intervals = IntervalTree()
            self.intervals.addi(self._begin, self._end)
            for child in self.children:
                # make sure all of our children are within our own interval
                child.intervals.chop(0, self._begin)
                if child.end_offset > self._end:
                    child.intervals.chop(self._end, child.end_offset)
                if child.begin_offset < child.end_offset:
                    # did we touch a byte more recently than one of our children? if so, rob them of that terminal
                    child.deconflict_parent(self)

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
                yield Interval(start_offset, last_offset + 1, self.value.uid)  # type: ignore
                start_offset = last_offset = offset
            else:
                # this is a contiguous byte sequence, so update its end
                last_offset = offset
        if start_offset is not None:
            yield Interval(start_offset, last_offset + 1, self.value.uid)  # type: ignore


def trace_to_non_generalized_tree(trace: PolyTrackerTrace) -> NonGeneralizedParseTree:
    tree = trace_to_tree(trace, NonGeneralizedParseTree, False)

    for node in tqdm(
        tree.postorder_traversal(),
        total=tree.descendants + 1,
        leave=False,
        desc=" deconflicting parse tree ranges",
        unit=" nodes",
    ):
        if isinstance(node.value, Start):
            node.intervals[0 : len(trace.inputstr)] = 0
        node.bottom_up_pass()

    for node in tqdm(
        tree.preorder_traversal(), total=tree.descendants + 1, leave=False, desc=" finalizing parse tree ranges", unit=" nodes"
    ):
        if isinstance(node.value, Terminal):
            continue
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
                terminal = NonGeneralizedParseTree(Terminal(trace.inputstr[last_end : child.begin_offset]))
                terminal.intervals.addi(last_end, child.begin_offset)
                new_children.append(terminal)
            new_children.append(child)
            last_end = child.end_offset
        if last_end < node_end:
            terminal = NonGeneralizedParseTree(Terminal(trace.inputstr[last_end:node_end]))
            terminal.intervals.addi(last_end, node_end)
            new_children.append(terminal)
        assert new_children
        node.children = new_children

    if __debug__:
        tree.verify(trace.inputstr)

    return tree
