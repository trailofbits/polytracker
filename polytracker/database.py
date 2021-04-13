from enum import IntEnum, IntFlag
from pathlib import Path
from typing import Iterable, Iterator, List, Optional, Set, Union

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.query import Query
from sqlalchemy import (
    BigInteger,
    BLOB,
    Column,
    create_engine,
    Enum as SQLEnum,
    ForeignKey,
    Integer,
    PrimaryKeyConstraint,
    Text,
    SmallInteger,
    UniqueConstraint,
)

from tqdm import tqdm

from .polytracker import ProgramTrace
from .repl import PolyTrackerREPL
from .tracing import (
    BasicBlock,
    BasicBlockEntry,
    BasicBlockType,
    ByteOffset,
    Function,
    FunctionEntry,
    FunctionReturn,
    Input,
    TaintAccess,
    Taints,
    TraceEvent,
)

Base = declarative_base()


class ByteAccessType(IntFlag):
    UNKNOWN_ACCESS = 0
    INPUT_ACCESS = 1
    CMP_ACCESS = 2
    READ_ACCESS = 4


class EventType(IntEnum):
    FUNC_ENTER = 0
    FUNC_RET = 1
    BLOCK_ENTER = 2
    TAINT_ACCESS = 3


class EdgeType(IntEnum):
    FORWARD = 0
    BACKWARD = 1


def stream_results(query: Query, window_size: int = 1000) -> Iterator:
    start = 0
    while True:
        stop = start + window_size
        results = query.slice(start, stop).all()
        if len(results) == 0:
            break
        yield from results
        start += window_size


class DBInput(Base, Input):  # type: ignore
    __tablename__ = "input"
    uid = Column("id", Integer, primary_key=True)
    stored_content = Column("content", BLOB, nullable=True)
    path = Column(Text)
    track_start = Column(BigInteger)
    track_end = Column(BigInteger)
    size = Column(BigInteger)
    trace_level = Column(Integer)

    events = relationship("DBTraceEvent", order_by="asc(DBTraceEvent.event_id)")


class DBFunction(Base, Function):  # type: ignore
    __tablename__ = "func"
    id = Column(Integer, primary_key=True)
    name = Column(Text)

    basic_blocks = relationship("DBBasicBlock")

    incoming_edges: Iterable["FunctionCFGEdge"] = relationship(
        "FunctionCFGEdge", primaryjoin="DBFunction.id==FunctionCFGEdge.dest_id"
    )
    outgoing_edges: Iterable["FunctionCFGEdge"] = relationship(
        "FunctionCFGEdge", primaryjoin="DBFunction.id==FunctionCFGEdge.src_id"
    )
    accessed_labels = relationship(
        "AccessedLabel",
        primaryjoin="and_(DBFunction.id==remote(DBBasicBlock.function_id), "
        "foreign(DBTraceEvent.block_gid)==DBBasicBlock.id, "
        "foreign(AccessedLabel.event_id)==DBTraceEvent.event_id)",
        viewonly=True,
    )

    def taints(self) -> Taints:
        return DBTaintForest.taints(
            (label.event.taint_forest_node for label in self.accessed_labels)
        )

    @property
    def function_index(self) -> int:  # type: ignore
        return self.id

    def calls_to(self) -> Set["Function"]:
        return {
            edge.dest
            for edge in self.outgoing_edges
            if edge.dest is not None and edge.edge_type == EdgeType.FORWARD
        }

    def called_from(self) -> Set["Function"]:
        return {
            edge.src
            for edge in self.incoming_edges
            if edge.src is not None and edge.edge_type == EdgeType.FORWARD
        }


class FunctionCFGEdge(Base):  # type: ignore
    __tablename__ = "func_cfg"
    dest_id = Column("dest", Integer, ForeignKey("func.id"))
    src_id = Column("src", Integer, ForeignKey("func.id"))
    input_id = Column(Integer, ForeignKey("input.id"))
    thread_id = Column(Integer)
    event_id = Column(BigInteger, ForeignKey("events.event_id"))
    edge_type = Column(SmallInteger, SQLEnum(EdgeType))

    dest = relationship(
        "DBFunction", foreign_keys=[dest_id], back_populates="incoming_edges"
    )
    src = relationship(
        "DBFunction", foreign_keys=[src_id], back_populates="outgoing_edges"
    )
    input = relationship("DBInput")
    event = relationship("DBTraceEvent")

    __table_args__ = (PrimaryKeyConstraint("input_id", "dest", "src"),)


class DBBasicBlock(Base, BasicBlock):  # type: ignore
    __tablename__ = "basic_block"
    id = Column(BigInteger, primary_key=True)
    # function_id should always be equal to (id >> 32), but we have it for convenience
    function_id = Column(BigInteger, ForeignKey("func.id"))
    attributes = Column("block_attributes", Integer, SQLEnum(BasicBlockType))

    __table_args__ = (UniqueConstraint("id", "block_attributes"),)

    events: Iterable["DBTraceEvent"] = relationship(
        "DBTraceEvent", order_by="asc(DBTraceEvent.event_id)"
    )
    accessed_labels = relationship(
        "AccessedLabel",
        primaryjoin="and_(DBBasicBlock.id==remote(DBTraceEvent.block_gid), "
        "foreign(AccessedLabel.event_id)==DBTraceEvent.event_id)",
        viewonly=True,
    )
    function = relationship("DBFunction", back_populates="basic_blocks")

    _children: Optional[Set[BasicBlock]] = None
    _predecessors: Optional[Set[BasicBlock]] = None

    @property
    def index_in_function(self) -> int:  # type: ignore
        return self.id & 0x0000FFFF

    def taints(self) -> Taints:
        return DBTaintForest.taints(
            (label.taint_forest_node for label in self.accessed_labels)
        )

    def _discover_neighbors(self):
        if self._children is not None and self._predecessors is not None:
            return
        self._children = set()
        self._predecessors = set()
        next_event_queue = []
        prev_event_queue = []
        with tqdm(
            desc=f"resolving neighborhood for event {self.id}",
            unit=" BBs",
            total=3,
            leave=False,
        ) as t:
            t.update(1)
            for event in tqdm(
                self.events, desc="processing", unit=" events", leave=False
            ):
                next_event = event.next_event
                if next_event is not None:
                    next_event_queue.append(next_event)
                prev_event = event.previous_event
                if prev_event is not None:
                    prev_event_queue.append(prev_event)
            t.update(1)
            with tqdm(
                desc="processing",
                unit="descendants",
                leave=False,
                total=len(next_event_queue),
            ) as d:
                while next_event_queue:
                    d.update(1)
                    next_event = next_event_queue.pop()
                    if isinstance(next_event, BasicBlockEntry):
                        if next_event.basic_block != self:
                            self._children.add(next_event.basic_block)
                    else:
                        grandchild = next_event.next_event
                        if grandchild is not None:
                            next_event_queue.append(grandchild)
                            d.total += 1
            t.update(1)
            with tqdm(
                desc="processing",
                unit="predecessors",
                leave=False,
                total=len(prev_event_queue),
            ) as d:
                while prev_event_queue:
                    d.update(1)
                    prev_event = prev_event_queue.pop()
                    if isinstance(prev_event, BasicBlockEntry):
                        if prev_event.basic_block != self:
                            self._predecessors.add(prev_event.basic_block)
                    else:
                        grandparent = prev_event.previous_event
                        if grandparent is not None:
                            prev_event_queue.append(grandparent)
                            d.total += 1

    @property
    def predecessors(self) -> Set[BasicBlock]:  # type: ignore
        self._discover_neighbors()
        return self._predecessors  # type: ignore

    @property
    def children(self) -> Set[BasicBlock]:  # type: ignore
        self._discover_neighbors()
        return self._children  # type: ignore


class AccessedLabel(Base):  # type: ignore
    __tablename__ = "accessed_label"
    event_id = Column(BigInteger, ForeignKey("events.event_id"))
    label = Column(Integer, ForeignKey("taint_forest.label"))
    access_type = Column(SmallInteger, SQLEnum(ByteAccessType))

    event = relationship("DBTaintAccess", uselist=False)

    __table_args__ = (PrimaryKeyConstraint("event_id", "label", "access_type"),)

    def __lt__(self, other):
        return hasattr(other, "label") and self.label < other.label

    def taints(self) -> Taints:
        return DBTaintForest.taints((self.taint_forest_node,))


class DBTraceEvent(Base):  # type: ignore
    __tablename__ = "events"
    event_id = Column(BigInteger)  # globally unique, globally sequential event counter
    thread_event_id = Column(
        BigInteger
    )  # unique-to-thread id, sequential within the thread
    event_type = Column(SmallInteger, SQLEnum(EventType))
    input_id = Column(Integer, ForeignKey("input.id"))
    thread_id = Column(Integer)
    block_gid = Column(BigInteger, ForeignKey("basic_block.id"))
    func_event_id = Column(BigInteger, ForeignKey("events.event_id"))

    __table_args__ = (PrimaryKeyConstraint("input_id", "event_id"),)

    input = relationship("DBInput", back_populates="events")
    basic_block = relationship("DBBasicBlock", back_populates="events")
    accessed_labels = relationship("AccessedLabel")

    __mapper_args__ = {"polymorphic_on": "event_type"}

    _queried_for_entry: bool = False
    _function_entry: Optional[FunctionEntry] = None

    @property
    def uid(self) -> int:  # type: ignore
        return self.event_id

    @property
    def function_entry(self) -> Optional[FunctionEntry]:
        if not self._queried_for_entry:
            try:
                self._function_entry = (
                    Session.object_session(self)
                    .query(DBFunctionEntry)
                    .filter(DBFunctionEntry.event_id == self.func_event_id)
                    .one()
                )
            except NoResultFound:
                self._function_entry = None
        return self._function_entry

    @property
    def next_event(self) -> Optional["TraceEvent"]:
        if not hasattr(self, "_next_event"):
            session = Session.object_session(self)
            try:
                setattr(
                    self,
                    "_next_event",
                    session.query(DBTraceEvent)
                    .filter(
                        DBTraceEvent.thread_event_id == self.thread_event_id + 1,
                        DBTraceEvent.thread_id == self.thread_id,
                    )
                    .one()
                )
                setattr(self._next_event, "_prev_event", self)
            except NoResultFound:
                setattr(self, "_next_event", None)
        return self._next_event

    @property
    def previous_event(self) -> Optional["TraceEvent"]:
        if not hasattr(self, "_prev_event"):
            session = Session.object_session(self)
            try:
                setattr(
                    self,
                    "_prev_event",
                    session.query(DBTraceEvent)
                    .filter(
                        DBTraceEvent.thread_event_id == self.thread_event_id - 1,
                        DBTraceEvent.thread_id == self.thread_id,
                    )
                    .one()
                )
                setattr(self._prev_event, "_next_event", self)
            except NoResultFound:
                setattr(self, "_prev_event", None)
        return self._prev_event

    @property
    def next_global_event(self) -> Optional["TraceEvent"]:
        session = Session.object_session(self)
        try:
            return (
                session.query(DBTraceEvent)
                .filter(DBTraceEvent.event_id == self.event_id + 1)
                .one()
            )
        except NoResultFound:
            return None

    @property
    def previous_global_event(self) -> Optional["TraceEvent"]:
        session = Session.object_session(self)
        try:
            return (
                session.query(DBTraceEvent)
                .filter(DBTraceEvent.event_id == self.event_id - 1)
                .one()
            )
        except NoResultFound:
            return None

    def taints(self) -> Taints:
        return Taints(())


class DBTaintAccess(DBTraceEvent, TaintAccess):  # type: ignore
    __mapper_args__ = {
        "polymorphic_identity": EventType.TAINT_ACCESS,  # type: ignore
    }

    accessed_label = relationship(
        "AccessedLabel",
        primaryjoin="AccessedLabel.event_id==DBTaintAccess.event_id",
        uselist=False,
    )
    taint_forest_node = relationship(
        "DBTaintForest",
        primaryjoin="and_(DBTaintAccess.event_id==remote(AccessedLabel.event_id), "
        "AccessedLabel.label==foreign(DBTaintForest.label), "
        "DBTaintForest.input_id==DBTaintAccess.input_id)",
        viewonly=True,
        uselist=False,
    )

    def taints(self) -> Taints:
        return DBTaintForest.taints((self.taint_forest_node,))


class DBBasicBlockEntry(DBTraceEvent, BasicBlockEntry):  # type: ignore
    __mapper_args__ = {
        "polymorphic_identity": EventType.BLOCK_ENTER,  # type: ignore
    }

    @property
    def bb_index(self) -> int:
        return self.block_gid & 0x0000FFFF

    @property
    def function_index(self) -> int:
        return (self.func_gid >> 32) & 0xFFFF

    def taint_accesses(self) -> Iterator[DBTaintAccess]:
        next_event = self.next_event
        while isinstance(next_event, DBTaintAccess):
            yield next_event
            next_event = next_event.next_event

    def taints(self) -> Taints:
        return DBTaintForest.taints(
            (access.taint_forest_node for access in self.taint_accesses())
        )


class DBFunctionEntry(DBTraceEvent, FunctionEntry):  # type: ignore
    __mapper_args__ = {"polymorphic_identity": EventType.FUNC_ENTER}  # type: ignore

    @property
    def function(self) -> Function:
        if self.basic_block is None:
            # this can happen on main()
            entrypoint = self.entrypoint
            if entrypoint is None:
                raise ValueError(f"Could not determine the function associated with {self!r}")
            return entrypoint.function
        else:
            return self.basic_block.function

    @property
    def function_return(self) -> Optional["FunctionReturn"]:
        try:
            return (
                Session.object_session(self)
                .query(DBFunctionReturn)
                .filter(DBFunctionReturn.func_event_id == self.uid)
                .one()
            )
        except NoResultFound:
            return None


class DBFunctionReturn(DBTraceEvent, FunctionReturn):  # type: ignore
    __mapper_args__ = {"polymorphic_identity": EventType.FUNC_RET}  # type: ignore


class DBProgramTrace(ProgramTrace):
    def __init__(self, session: Session):
        self.session: Session = session

    @staticmethod
    @PolyTrackerREPL.register("load_trace")
    def load(db_path: Union[str, Path]) -> "DBProgramTrace":
        """loads a trace from the database emitted by an instrumented binary"""
        engine = create_engine(f"sqlite:///{db_path!s}")
        session_maker = sessionmaker(bind=engine)
        db = DBProgramTrace(session_maker())
        if db_path != ":memory:" and sum(1 for _ in db.inputs) > 1:
            raise ValueError(f"{db_path} contains traces from multiple inputs.\nIt is likely the case that the same "
                             "database was reused for more than one run of the instrumented binary.\nThis feature is "
                             "not yet fully implemented.\nPlease track this GitHub issue for further details and "
                             "progress:\n    https://github.com/trailofbits/polytracker/issues/6353\nIn the mean time, "
                             "you should use a separate database for every instrumented run of a binary.")
        return db

    def __len__(self) -> int:
        return self.session.query(DBTraceEvent).count()

    def __iter__(self) -> Iterator[TraceEvent]:
        return stream_results(
            self.session.query(DBTraceEvent).order_by(DBTraceEvent.event_id.asc())
        )

    @property
    def functions(self) -> Iterable[Function]:
        return self.session.query(DBFunction)

    def get_function(self, name: str) -> Function:
        try:
            return (
                self.session.query(DBFunction).filter(DBFunction.name.like(name)).one()
            )
        except NoResultFound:
            pass
        raise KeyError(name)

    def has_function(self, name: str) -> bool:
        return self.session.query(DBFunction).filter(DBFunction.name.like(name)).limit(1).count() > 0

    @property
    def basic_blocks(self) -> Iterable[BasicBlock]:
        return self.session.query(DBBasicBlock)

    def access_sequence(self) -> Iterator[TaintAccess]:
        yield from stream_results(
            self.session.query(DBTaintAccess).order_by(DBTaintAccess.event_id.asc())
        )

    @property
    def num_accesses(self) -> int:
        return self.session.query(DBTaintAccess).count()

    @property
    def inputs(self) -> Iterable[Input]:
        return self.session.query(DBInput)

    def __getitem__(self, uid: int) -> TraceEvent:
        raise NotImplementedError()

    def __contains__(self, uid: int):
        raise NotImplementedError()


class PolytrackerItem(Base):  # type: ignore
    __tablename__ = "polytracker"
    store_key = Column(Text)
    value = Column(Text)
    __table_args__ = (PrimaryKeyConstraint("store_key", "value"),)


class CanonicalMap(Base):  # type: ignore
    __tablename__ = "canonical_map"
    input_id = Column(Integer, ForeignKey("input.id"))
    taint_label = Column(BigInteger)
    file_offset = Column(BigInteger)

    __table_args__ = (PrimaryKeyConstraint("input_id", "taint_label", "file_offset"),)

    input = relationship("DBInput")


class TaintedChunksItem(Base):  # type: ignore
    __tablename__ = "tainted_chunks"
    input_id = Column(Integer, ForeignKey("input.id"))
    start_offset = Column(BigInteger)
    end_offset = Column(BigInteger)
    __table_args__ = (PrimaryKeyConstraint("input_id", "start_offset", "end_offset"),)


class DBTaintForest(Base):  # type: ignore
    __tablename__ = "taint_forest"
    parent_one_id = Column("parent_one", Integer, ForeignKey("taint_forest.label"))
    parent_two_id = Column("parent_two", Integer, ForeignKey("taint_forest.label"))
    label = Column(Integer, ForeignKey("accessed_label.label"))
    input_id = Column(Integer, ForeignKey("input.id"))

    __table_args__ = (PrimaryKeyConstraint("input_id", "label"),)

    parent_one = relationship(
        "DBTaintForest", foreign_keys=[parent_one_id, input_id], uselist=False
    )
    parent_two = relationship(
        "DBTaintForest", foreign_keys=[parent_two_id, input_id], uselist=False
    )
    input = relationship("DBInput")
    accessed_labels = relationship("AccessedLabel", foreign_keys=[label, input_id])

    def __hash__(self):
        return hash((self.input_id, self.label))

    def __eq__(self, other):
        return (
            isinstance(other, DBTaintForest)
            and self.input_id == other.input_id
            and self.label == other.label
        )

    def __lt__(self, other):
        return isinstance(other, DBTaintForest) and self.label < other.label

    def __str__(self):
        return f"I{self.input_id}L{self.label}"

    @staticmethod
    def taints(labels: Iterable["DBTaintForest"]) -> Taints:
        # reverse the labels to reduce the likelihood of reproducing work
        history: Set[DBTaintForest] = set(labels)
        node_stack: List[DBTaintForest] = sorted(list(set(history)), reverse=True)
        taints: Set[ByteOffset] = set()
        if len(node_stack) < 10:
            labels_str = ", ".join(map(str, node_stack))
        else:
            labels_str = f"{len(node_stack)} labels"
        session: Optional[Session] = None
        with tqdm(
            desc=f"finding canonical taints for {labels_str}",
            leave=False,
            delay=5.0,
            bar_format="{l_bar}{bar}| [{elapsed}<{remaining}, {rate_fmt}{postfix}]'",
            total=sum(node.label for node in node_stack),
        ) as t:
            while node_stack:
                node = node_stack.pop()
                t.update(node.label)
                if node.parent_one_id == 0:
                    assert node.parent_two_id == 0
                    if session is None:
                        session = Session.object_session(node)
                    try:
                        file_offset = (
                            session.query(CanonicalMap)
                            .filter(
                                CanonicalMap.taint_label == node.label,
                                CanonicalMap.input_id == node.input_id,
                            )
                            .one()
                            .file_offset
                        )
                    except NoResultFound:
                        raise ValueError(
                            f"Taint label {node.label} is not in the canonical mapping!"
                        )
                    taints.add(ByteOffset(source=node.input, offset=file_offset))
                else:
                    parent1, parent2 = node.parent_one, node.parent_two
                    if parent1 not in history:
                        history.add(parent1)
                        node_stack.append(parent1)
                        t.total += parent1.label
                    if parent2 not in history:
                        history.add(parent2)
                        node_stack.append(parent2)
                        t.total += parent2.label
        return Taints(taints)
