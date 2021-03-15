from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, BigInteger, PrimaryKeyConstraint, UniqueConstraint, \
    ForeignKeyConstraint, Text, ForeignKey

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


class BlockInstanceItem(Base):
    __tablename__ = "block_instance"
    event_id = Column(BigInteger)
    function_call_id = Column(Integer, ForeignKey("func_call.event_id"))
    block_gid = Column(BigInteger, ForeignKey("basic_block.id"))
    entry_count = Column(BigInteger)
    thread_id = Column(Integer)
    input_id = Column(Integer, ForeignKey("input.id"))
    __table_args__ = (PrimaryKeyConstraint("event_id", "thread_id", "input_id"),)


# TODO (Carson) have method to create TraceObjects from each method
class FunctionRetItem(Base):
    __tablename__ = 'func_ret'
    event_id = Column(BigInteger)
    function_index = Column(Integer, ForeignKey("func.id"))
    ret_event_uid = Column(BigInteger)
    call_event_uid = Column(BigInteger)
    thread_id = Column(Integer)
    input_id = Column(Integer, ForeignKey("input.id"))

    __table_args__ = (
        PrimaryKeyConstraint('input_id', 'thread_id', 'event_id'),
    )


class FunctionCallItem(Base):
    __tablename__ = "func_call"
    event_id = Column(BigInteger)
    function_index = Column(Integer, ForeignKey("func.id"))
    callee_index = Column(BigInteger)
    ret_event_uid = Column(BigInteger)
    consumes_bytes = Column(Integer)
    thread_id = Column(Integer)
    input_id = Column(Integer, ForeignKey("input.id"))
    __table_args__ = (PrimaryKeyConstraint("event_id", "thread_id", "input_id"),)


class TaintItem(Base):
    __tablename__ = "accessed_label"
    block_gid = Column(BigInteger, ForeignKey("block_instance.block_gid"))
    event_id = Column(BigInteger)
    label = Column(Integer)
    input_id = Column(Integer, ForeignKey("input.id"))
    access_type = Column(Integer)
    __table_args__ = (PrimaryKeyConstraint("event_id", "block_gid", "label", "input_id", "access_type"),
                     UniqueConstraint("block_gid", "label", "input_id"))


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

