from pathlib import Path
from typing import Iterable, Optional, Type, TypeVar, Union

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy import (
    Column,
    create_engine,
    Integer,
    BigInteger,
    PrimaryKeyConstraint,
    UniqueConstraint,
    Text,
    ForeignKey,
)

from .tracing import (
    FunctionCall,
    FunctionReturn,
    TraceEvent,
    PolyTrackerTrace,
    BasicBlockEntry,
    BasicBlock,
    Function,
)

Base = declarative_base()


class InputItem(Base):
    __tablename__ = "input"
    id = Column(Integer, primary_key=True)
    path = Column(Text)
    track_start = Column(BigInteger)
    track_end = Column(BigInteger)
    size = Column(BigInteger)
    trace_level = Column(Integer)


class FunctionItem(Base):
    __tablename__ = "func"
    id = Column(Integer, primary_key=True)
    name = Column(Text)


class BasicBlockItem(Base):
    __tablename__ = "basic_block"
    id = Column(BigInteger, primary_key=True)
    block_attributes = Column(Integer)
    # __table_args__ = (UniqueConstraint('id', 'block_attributes'),)


T = TypeVar("T", bound=TraceEvent)


class DBTraceEvent:
    BASE_EVENT_TYPE: Type[TraceEvent]

    def __class_getitem__(
        cls, trace_event_type: Type[T]
    ) -> Type[Union["DBTraceEvent", T]]:
        return type(
            f"DB{trace_event_type.__name__}Mixin",
            (DBTraceEvent, trace_event_type),
            {"BASE_EVENT_TYPE": trace_event_type},
        )

    @property
    def previous_uid(self) -> Optional[int]:
        return self.uid - 1 if self.uid > 1 else None

    @property
    def next_uid(self) -> Optional[int]:
        # TODO: Check if we are the last event
        return self.uid + 1


class DBBasicBlockEntry(Base, DBTraceEvent[BasicBlockEntry]):
    __tablename__ = "block_instance"
    uid = Column("event_id", BigInteger)
    function_call_uid = Column(
        "function_call_id", Integer, ForeignKey("func_call.event_id")
    )
    global_index = Column("block_gid", BigInteger, ForeignKey("basic_block.id"))
    entry_count = Column(BigInteger)
    thread_id = Column(Integer)
    input_id = Column(Integer, ForeignKey("input.id"))
    __table_args__ = (PrimaryKeyConstraint("event_id", "thread_id", "input_id"),)

    consumed: Iterable[int] = ()

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


class DBFunctionReturn(Base, DBTraceEvent[FunctionReturn]):
    __tablename__ = "func_ret"
    uid = Column("event_id", BigInteger)
    function_index = Column(Integer, ForeignKey("func.id"))
    returning_to_uid = Column("ret_event_uid", BigInteger)
    call_event_uid = Column(BigInteger)
    thread_id = Column(Integer)
    input_id = Column(Integer, ForeignKey("input.id"))

    __table_args__ = (PrimaryKeyConstraint("input_id", "thread_id", "event_id"),)


class DBFunctionCall(Base, DBTraceEvent[FunctionCall]):
    __tablename__ = "func_call"
    uid = Column("event_id", BigInteger)
    function_index = Column(Integer, ForeignKey("func.id"))
    callee_index = Column(BigInteger)
    return_uid = Column("ret_event_uid", BigInteger)
    _consumes_bytes = Column("consumes_bytes", Integer)
    thread_id = Column(Integer)
    input_id = Column(Integer, ForeignKey("input.id"))
    __table_args__ = (PrimaryKeyConstraint("event_id", "thread_id", "input_id"),)

    @property
    def consumes_bytes(self) -> bool:
        return bool(self._consumes_bytes)


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
        pass

    @property
    def basic_blocks(self) -> Iterable[BasicBlock]:
        pass

    def get_basic_block(self, entry: BasicBlockEntry) -> BasicBlock:
        pass

    def __getitem__(self, uid: int) -> TraceEvent:
        pass

    def __contains__(self, uid: int):
        pass


class TaintItem(Base):
    __tablename__ = "accessed_label"
    block_gid = Column(BigInteger, ForeignKey("block_instance.block_gid"))
    event_id = Column(BigInteger)
    label = Column(Integer)
    input_id = Column(Integer, ForeignKey("input.id"))
    access_type = Column(Integer)
    __table_args__ = (
        PrimaryKeyConstraint(
            "event_id", "block_gid", "label", "input_id", "access_type"
        ),
        UniqueConstraint("block_gid", "label", "input_id"),
    )


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


class FunctionCFGItem(Base):
    __tablename__ = "func_cfg"
    callee = Column(Integer, ForeignKey("func.id"))
    caller = Column(Integer, ForeignKey("func.id"))
    input_id = Column(Integer, ForeignKey("input.id"))
    event_id = Column(BigInteger)
    __table_args__ = (PrimaryKeyConstraint("input_id", "callee", "caller"),)


class TaintForestItem(Base):
    __tablename__ = "taint_forest"
    parent_one = Column(Integer)
    parent_two = Column(Integer)
    label = Column(Integer, ForeignKey("accessed_label.label"))
    input_id = Column(Integer, ForeignKey("input.id"))
    __table_args__ = (PrimaryKeyConstraint("input_id", "label"),)
