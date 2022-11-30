import sys
import os

DUMP_PASS_LIB: str = sys.argv[1]
CXX_BC_DIR: str = sys.argv[2]
OUTFILE: str = sys.argv[3]
assert os.path.exists(CXX_BC_DIR)

items = os.listdir(CXX_BC_DIR)
for item in items:
    os.system(
        f"opt --enable-new-pm=0 -load {DUMP_PASS_LIB} --dump -o doesnt_matter.bc {item} >> {OUTFILE}"
    )
