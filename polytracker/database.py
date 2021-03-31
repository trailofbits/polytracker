from enum import IntEnum, IntFlag
from pathlib import Path
from typing import Iterable, Optional, Union

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm.session import Session
from sqlalchemy import (
    BigInteger,
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

from .tracing import (
    BasicBlock,
    BasicBlockEntry,
    BasicBlockType,
    Function,
    FunctionCall,
    FunctionReturn,
    PolyTrackerTrace,
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


class EdgeType(IntEnum):
    FORWARD = 0
    BACKWARD = 1


class Input(Base):
    __tablename__ = "input"
    id = Column(Integer, primary_key=True)
    path = Column(Text)
    track_start = Column(BigInteger)
    track_end = Column(BigInteger)
    size = Column(BigInteger)
    trace_level = Column(Integer)

    events = relationship("DBTraceEvent")


class DBFunction(Base):
    __tablename__ = "func"
    id = Column(Integer, primary_key=True)
    name = Column(Text)

    basic_blocks = relationship("DBBasicBlock")

    incoming_edges = relationship("FunctionCFGEdge", primaryjoin="DBFunction.id==FunctionCFGEdge.dest_id")
    outgoing_edges = relationship("FunctionCFGEdge", primaryjoin="DBFunction.id==FunctionCFGEdge.src_id")
    accessed_labels = relationship("AccessedLabel",
                                   primaryjoin="and_(DBFunction.id==remote(DBBasicBlock.function_id), "
                                               "foreign(AccessedLabel.block_gid)==DBBasicBlock.id)",
                                   viewonly=True)

    def __repr__(self):
        return f"Function(id={self.id}, name={self.name!r})"


class FunctionCFGEdge(Base):
    __tablename__ = "func_cfg"
    dest_id = Column("dest", Integer, ForeignKey("func.id"))
    src_id = Column("src", Integer, ForeignKey("func.id"))
    input_id = Column(Integer, ForeignKey("input.id"))
    thread_id = Column(Integer)
    event_id = Column(BigInteger, ForeignKey("events.event_id"))
    edge_type = Column(SmallInteger, SQLEnum(EdgeType))

    dest = relationship("DBFunction", foreign_keys=[dest_id], back_populates="incoming_edges")
    src = relationship("DBFunction", foreign_keys=[src_id], back_populates="outgoing_edges")
    input = relationship("Input")
    event = relationship("DBTraceEvent")

    __table_args__ = (PrimaryKeyConstraint("input_id", "dest", "src"),)


class DBBasicBlock(Base, BasicBlock):
    __tablename__ = "basic_block"
    id = Column(BigInteger, primary_key=True)
    # function_id should always be equal to (id >> 32), but we have it for convenience
    function_id = Column(BigInteger, ForeignKey("func.id"))
    attributes = Column("block_attributes", Integer, SQLEnum(BasicBlockType))

    __table_args__ = (UniqueConstraint("id", "block_attributes"),)

    accessed_labels = relationship("AccessedLabel")
    function = relationship("DBFunction", back_populates="basic_blocks")

    @hybrid_property
    def bb_index(self) -> int:
        return self.id & 0x0000FFFF

    def __str__(self):
        return f"{self.function.name}@{self.bb_index}"


class AccessedLabel(Base):
    __tablename__ = "accessed_label"
    block_gid = Column(BigInteger, ForeignKey("basic_block.id"))
    event_id = Column(BigInteger, ForeignKey("events.event_id"))
    label = Column(Integer)
    input_id = Column(Integer)
    access_type = Column(SmallInteger, SQLEnum(ByteAccessType))
    thread_id = Column(Integer)

    event = relationship("DBTraceEvent", back_populates="accessed_labels")
    basic_block = relationship("DBBasicBlock", back_populates="accessed_labels")

    __table_args__ = (
        PrimaryKeyConstraint(
            "block_gid", "event_id", "label", "input_id", "access_type"
        ),
    )


class DBTraceEvent(Base):
    __tablename__ = "events"
    event_id = Column(BigInteger)
    event_type = Column(SmallInteger, SQLEnum(EventType))
    input_id = Column(Integer, ForeignKey("input.id"))
    thread_id = Column(Integer)
    block_gid = Column(BigInteger)

    __table_args__ = (PrimaryKeyConstraint("input_id", "event_id"),)

    input = relationship("Input", back_populates="events")
    accessed_labels = relationship("AccessedLabel")

    __mapper_args__ = {"polymorphic_on": "event_type"}

    @property
    def uid(self) -> int:
        return self.event_id

    @property
    def previous_uid(self) -> Optional[int]:
        return self.uid - 1 if self.uid > 1 else None

    @property
    def next_uid(self) -> Optional[int]:
        # TODO: Check if we are the last event
        return self.uid + 1


class DBBasicBlockEntry(DBTraceEvent, BasicBlockEntry):
    __mapper_args__ = {
        "polymorphic_identity": EventType.BLOCK_ENTER,
    }

    @BasicBlockEntry.trace.setter  # type: ignore
    def trace(self, pttrace: "PolyTrackerTrace"):
        if isinstance(pttrace, DBPolyTrackerTrace):
            BasicBlockEntry.trace.fset(self, pttrace)  # type: ignore
            consumed_bytes = []
            for taint_item in pttrace.session.query(TaintItem).filter(
                TaintItem.input_id == self.input_id
                and TaintItem.block_gid == self.global_index
            ):
                consumed_bytes.append(taint_item.label)
            self.consumed = tuple(consumed_bytes)
        else:
            raise ValueError(
                f"{self.__class__.__name__}.trace may only be set to subclasses of `DBPolyTrackerTrace`"
            )

    @property
    def bb_index(self) -> int:
        return self.block_gid & 0x0000FFFF

    @property
    def function_index(self) -> int:
        return (self.func_gid >> 32) & 0xFFFF


class DBFunctionCall(DBTraceEvent, FunctionCall):
    __mapper_args__ = {"polymorphic_identity": EventType.FUNC_ENTER}


class DBFunctionReturn(DBTraceEvent, FunctionReturn):
    __mapper_args__ = {"polymorphic_identity": EventType.FUNC_RET}


class DBPolyTrackerTrace(PolyTrackerTrace):
    def __init__(self, session: Session):
        self.session: Session = session

    @staticmethod
    def load(db_path: Union[str, Path]) -> "DBPolyTrackerTrace":
        engine = create_engine(f"sqlite:///{db_path!s}")
        session_maker = sessionmaker(bind=engine)
        return DBPolyTrackerTrace(session_maker())

    def __len__(self) -> int:
        pass

    def __iter__(self) -> Iterable[TraceEvent]:
        pass

    @property
    def functions(self) -> Iterable[Function]:
        return self.session.query(DBFunction).all()

    def get_function(self, name: str) -> Function:
        try:
            return self.session.query(DBFunction).filter(DBFunction.name.like(name)).one()
        except NoResultFound:
            raise KeyError(name)

    @property
    def basic_blocks(self) -> Iterable[BasicBlock]:
        return self.session.query(DBBasicBlock).all()

    def get_basic_block(self, entry: BasicBlockEntry) -> BasicBlock:
        pass

    def __getitem__(self, uid: int) -> TraceEvent:
        pass

    def __contains__(self, uid: int):
        pass


class PolytrackerItem(Base):
    __tablename__ = "polytracker"
    store_key = Column(Text)
    value = Column(Text)
    __table_args__ = (PrimaryKeyConstraint("store_key", "value"),)


class CanonicalMapItem(Base):
    __tablename__ = "canonical_map"
    input_id = Column(Integer, ForeignKey("input.id"))
    taint_label = Column(BigInteger)
    file_offset = Column(BigInteger)
    __table_args__ = (PrimaryKeyConstraint("input_id", "taint_label", "file_offset"),)


class TaintedChunksItem(Base):
    __tablename__ = "tainted_chunks"
    input_id = Column(Integer, ForeignKey("input.id"))
    start_offset = Column(BigInteger)
    end_offset = Column(BigInteger)
    __table_args__ = (PrimaryKeyConstraint("input_id", "start_offset", "end_offset"),)


class TaintForestItem(Base):
    __tablename__ = "taint_forest"
    parent_one = Column(Integer)
    parent_two = Column(Integer)
    label = Column(Integer, ForeignKey("accessed_label.label"))
    input_id = Column(Integer, ForeignKey("input.id"))
    __table_args__ = (PrimaryKeyConstraint("input_id", "label"),)
