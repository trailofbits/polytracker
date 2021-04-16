import pytest

from polytracker import ProgramTrace
from polytracker.grammars import extract

from .test_polytracker import program_trace


@pytest.mark.program_trace("test_fgetc.c", input="ABCDEFGH")
def test_extract(program_trace: ProgramTrace):
    grammar = extract([program_trace], simplify=False)
    grammar.verify()
    print(str(grammar))


@pytest.mark.program_trace("test_fgetc.c", input="ABCDEFGH")
def test_simplify(program_trace: ProgramTrace):
    grammar = extract([program_trace], simplify=True)
    grammar.verify()
    print(str(grammar))
