from collections import defaultdict
import pytest
from typing import Dict, Set

from polytracker import BasicBlock, BasicBlockEntry, FunctionReturn, ProgramTrace


@pytest.mark.program_trace("test_bb_splitting.c")
def test_bb_splitting(program_trace: ProgramTrace):
    """Ensure that every basic block has at most one funtion call or one conditional branch"""
    entrypoint = program_trace.entrypoint
    assert entrypoint is not None
    assert entrypoint.function.name == "main"
    jumps_to: Dict[BasicBlock, Set[BasicBlock]] = defaultdict(set)
    must_not_be_conditional: Set[BasicBlock] = set()
    indent = 0
    for event in program_trace:
        if not isinstance(event, BasicBlockEntry):
            if isinstance(event, FunctionReturn):
                func_name = event.returning_from.name
                print(f"RETURNING FROM: {'  ' * indent}{func_name}")
                indent -= 2
            continue
        func = event.called_function
        print(f"{'  ' * indent}{event}")
        if func is not None:
            # make sure the function returns to a basic block that is not conditional
            assert func.function_return is not None
            must_not_be_conditional.add(event.basic_block)
            indent += 1
            print(f"{'  ' * indent}{func}")
            indent += 1
        else:
            if event.next_event is not None:
                jumps_to[event.basic_block].add(event.next_event.basic_block)
    for bb in must_not_be_conditional:
        assert len(jumps_to[bb]) < 2, (
            f"Basic block {bb} is the return site for a function, but it is conditional; it"
            f" jumps to {', '.join(map(str, jumps_to[bb]))}"
        )
