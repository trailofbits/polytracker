import sys
import os

MAIN_LIST: str = sys.argv[1]
CXX_LIST: str = sys.argv[2]
assert os.path.exists(MAIN_LIST)
assert os.path.exists(CXX_LIST)

main_items = []
new_items = []
with open(MAIN_LIST, "r") as main_file:
    items = main_file.readlines()
    for item in items:
        end_pos = item.find("=")
        main_items.append(item[4:end_pos])

with open(CXX_LIST, "r") as cxx_file:
    items = cxx_file.readlines()
    for item in items:
        pos = item.find("=")
        filt_item = item[4:pos]
        if filt_item in main_items:
            continue
        else:
            new_items.append(item)

for item in new_items:
    print(item)
