from abc import ABC, abstractmethod
from logging import getLogger
from typing import Generic, Iterable, Iterator, List, Optional, Tuple, Type, TypeVar, Union

from intervaltree import Interval, IntervalTree
from tqdm import tqdm

from .cfg import DAG
from .tracing import BasicBlockEntry, FunctionInvocation, ProgramTrace, TraceEvent


log = getLogger(__file__)


V = TypeVar("V")
T = TypeVar("T", bound="ParseTree")


class ParseTree(ABC, Generic[V]):
    __slots__ = "value", "_descendants"

    def __init__(self, value: V):
        self.value: V = value
        self._descendants: Optional[int] = None

    @property
    @abstractmethod
    def children(self: T) -> List[T]:
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
                s.extend((False, child) for child in reversed(node.children))  # type: ignore
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

    def leaves(self: T) -> Iterator[T]:
        for t in self.preorder_traversal():
            if t.is_leaf():
                yield t  # type: ignore

    def __getitem__(self: T, child_index: int) -> T:
        return self.children[child_index]

    def __iter__(self: T) -> Iterator[T]:
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


IPT = TypeVar("IPT", bound="ImmutableParseTree")


class ImmutableParseTree(Generic[V], ParseTree[V]):
    __slots__ = "_children"

    def __init__(self: IPT, value: V, children: Iterable[IPT] = ()):
        super().__init__(value)
        self._children: List[IPT] = list(children)

    @property
    def children(self: IPT) -> List[IPT]:
        return self._children

    def clone(self: IPT) -> IPT:
        class IPTNode:
            def __init__(self, node: IPT, parent: Optional["IPTNode"] = None):  # noqa: F821
                self.node: IPT = node
                self.children: Optional[List[IPT]] = None
                self.parent: Optional[IPTNode] = parent

        to_clone: List[IPTNode] = [IPTNode(self)]
        while to_clone:
            ipt_node = to_clone[-1]
            if ipt_node.children is None:
                ipt_node.children = []
                to_clone.extend(IPTNode(child, ipt_node) for child in reversed(ipt_node.node.children))
            else:
                to_clone.pop()
                cloned = self.__class__(value=ipt_node.node.value, children=ipt_node.children)
                if ipt_node.parent is not None:
                    assert ipt_node.parent.children is not None
                    ipt_node.parent.children.append(cloned)
                else:
                    assert len(to_clone) == 0
                    return cloned
        raise ValueError("This should never be reachable")


MPT = TypeVar("MPT", bound="MutableParseTree")


class MutableParseTree(Generic[V], ImmutableParseTree[V]):
    @ImmutableParseTree.children.setter  # type: ignore
    def children(self: MPT, new_children: List[MPT]):
        self._children = new_children

    def add_child(self: MPT, new_child: MPT):
        self._children.append(new_child)

    def __setitem__(self: MPT, child_index: int, new_child: MPT):
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
    trace: ProgramTrace,
    node_type: Type[N] = ParseTree[Union[Start, TraceEvent, Terminal]],  # type: ignore
    include_terminals: bool = True,
) -> N:
    if trace.entrypoint is None:
        raise ValueError(f"Trace {trace} does not have an entrypoint!")

    root: N = node_type(Start())

    entrypoint_node = node_type(trace.entrypoint)
    root.children.append(entrypoint_node)
    function_stack: List[Tuple[FunctionInvocation, N]] = [(trace.entrypoint, entrypoint_node)]

    with tqdm(
        unit=" functions", leave=False, desc="extracting a parse tree", total=trace.num_function_calls_that_touched_taint()
    ) as t:
        while function_stack:
            function, node = function_stack.pop()
            t.update(1)
            for bb in tqdm(
                function.basic_blocks(), unit=" basic blocks", leave=False, desc=function.function.demangled_name, delay=1.0
            ):
                child_node = node_type(bb)
                node.children.append(child_node)
                if include_terminals:
                    for token in bb.get_taints().regions():
                        node.children.append(node_type(Terminal(token.value)))
                func = bb.called_function
                if func is not None:
                    if not func.touched_taint:
                        log.debug(f"skipping call to {func.function.demangled_name} because it did not touch taint")
                        continue
                    child_node = node_type(func)
                    node.children.append(child_node)
                    function_stack.append((func, child_node))

    return root


G = TypeVar("G", bound="NonGeneralizedParseTree")


class NonGeneralizedParseTree(MutableParseTree[Union[Start, TraceEvent, Terminal]]):
    def __init__(self: G, value: Union[Start, TraceEvent, Terminal], children: Iterable[G] = ()):
        super().__init__(value=value, children=children)
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
                overlap = ", ".join([interval.data for interval in covered_input_bytes[child.begin_offset: child.end_offset]])
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
        for region in self.value.taints().regions():
            yield Interval(region.offset, region.offset + region.length, self.value.uid)


def trace_to_non_generalized_tree(trace: ProgramTrace) -> NonGeneralizedParseTree:
    tree = trace_to_tree(trace, NonGeneralizedParseTree, False)

    inputs = list(trace.inputs)
    if len(inputs) != 1:
        raise ValueError(f"Trace {trace!r} must have exactly one input; found {len(inputs)}")
    inputstr = inputs[0].content

    for node in tqdm(
        tree.postorder_traversal(),
        total=tree.descendants + 1,
        leave=False,
        desc=" deconflicting parse tree ranges",
        unit=" nodes",
    ):
        if isinstance(node.value, Start):
            node.intervals[0: len(inputstr)] = 0
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
                terminal = NonGeneralizedParseTree(Terminal(inputstr[last_end: child.begin_offset]))
                terminal.intervals.addi(last_end, child.begin_offset)
                new_children.append(terminal)
            new_children.append(child)
            last_end = child.end_offset
        if last_end < node_end:
            terminal = NonGeneralizedParseTree(Terminal(inputstr[last_end:node_end]))
            terminal.intervals.addi(last_end, node_end)
            new_children.append(terminal)
        assert new_children
        node.children = new_children

    if __debug__:
        tree.verify(inputstr)

    return tree
