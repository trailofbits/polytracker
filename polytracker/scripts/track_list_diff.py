from typing import Dict, List

import sys
import os
from collections import defaultdict
import argparse

"""
This file reads in two Polytracker ABI lists and produces
a list of functions that are declared multiple times within the corpus

If something is flagged as uninstrumented, that is okay, because tagging it with another attribute overrides
uninstrumented. The order is custom > functional > discard, (in regular DFSan its functional > discard > custom).

This file looks for conflicts related to declaring functions as functional/discard/custom within and across files
"""

# This function does not touch
DISCARD = "discard"
UNINST = "uninstrumented"
CUSTOM = "custom"
FUNC = "functional"

"""
This function checks for conflicts within a single file
It returns the conflicts found, and all the functions/attributes declared within a single file
"""


def analyze_abi_file(filename):
    file_conflicts: Dict[str, str] = defaultdict()
    func_attrs: Dict[str, List[str]] = defaultdict(list)
    with open(filename, "r") as curr_file:
        all_lines = curr_file.readlines()
        for line in all_lines:
            # This skips all non definition lines
            if line[0] != "f":
                continue
            fname, val = line[4:].split("=")
            val = val.strip()
            if val == UNINST:
                continue
            if fname in func_attrs:
                if val not in func_attrs[fname]:
                    file_conflicts[fname] = f"Multiple attributes set for {fname}"
                # Val is not value or discard, and we have seen a value before.
                else:
                    file_conflicts[fname] = f"Redefinition of attribute for {fname}"
            else:
                func_attrs[fname].append(val)
    return file_conflicts, func_attrs


"""
Returns True if two lists are different
if they are the same length and have the same items they are the same.
"""


def list_diff(list1, list2):
    if len(list1) != len(list2):
        return True
    for item in list1:
        if item not in list2:
            return True
    return False


"""
This function attempts to auto resolve conflicts between diffs by commenting out
all conflicts in one of the files. The typical usecase for this is when you generate a stublist of a library,
creating a list that has entries that are all discard. But you want to instrument a few functions, so in another file
you declare some of them as custom. This function can go and comment out all the discard ones so there are no
accidental conflicts between the two.
"""


def auto_resolve_conflicts(filename, diff_conflicts):
    with open(filename, "r+") as curr_file:
        file_contents = curr_file.readlines()
        for i, line in enumerate(file_contents):
            if line[0] != "f":
                continue
            fname, val = line[4:].split("=")
            if fname in diff_conflicts:
                file_contents[i] = "#" + file_contents[i]
        curr_file.seek(0)
        curr_file.write("".join(file_contents))
        curr_file.truncate()


# What would a directory look like?
def main():
    parser = argparse.ArgumentParser(
        description="""
        A utility to analyze two ABI lists to look for conflicts between them. A conflict comes in the form of
        one file declaring a function to be <functional, discard, custom> while another disagrees.
        """
    )
    parser.add_argument(
        "--file-one", "-f1", type=str, default=None, help="Path to first ABI file"
    )
    parser.add_argument(
        "--file-two", "-f2", type=str, default=None, help="Path to second ABI file"
    )
    parser.add_argument(
        "--choose-file", "-cf", type=int, default=None, help="Take all from file 1 or 2"
    )

    args = parser.parse_args(sys.argv[1:])

    if args.file_one is None:
        print("Error! File one not specified!")
        sys.exit(1)

    if args.file_two is None:
        print("Error! File two not specified!")
        sys.exit(1)

    if os.path.exists(args.file_one) is False:
        print(f"Error! File {args.file_one} could not be found!")
        sys.exit(1)

    if os.path.exists(args.file_two) is False:
        print(f"Error! File {args.file_two} could not be found!")
        sys.exit(1)

    f1_conflicts, f1_func_attrs = analyze_abi_file(args.file_one)
    f2_conflicts, f2_func_attrs = analyze_abi_file(args.file_two)
    diff_conflicts = [
        file
        for file in f1_func_attrs.keys()
        if file in f2_func_attrs.keys()
        and list_diff(f1_func_attrs[file], f2_func_attrs[file])
    ]
    if args.choose_file is not None:
        print(args.choose_file)
        truth_file = int(args.choose_file)
        if truth_file != 1 and truth_file != 2:
            print("Error! Invalid choose-file value, pick 1 or 2!")
            sys.exit(1)
        # Comment out conflicts in file 2
        if truth_file == 1:
            auto_resolve_conflicts(args.file_two, diff_conflicts)
        else:
            auto_resolve_conflicts(args.file_one, diff_conflicts)
        sys.exit(0)
    # If we found conflicts in any of the lists, make sure to exit 1 for CI
    conflicts_found = False
    if len(f1_conflicts) > 0:
        conflicts_found = True
        print("=" * 10, "FILE 1 CONFLICTS", "=" * 10)
        for file in f1_conflicts:
            print(f"FILE: {file}, CONFLICT:{f1_conflicts[file]}")
    if len(f2_conflicts) > 0:
        conflicts_found = True
        print("=" * 10, "FILE 2 CONFLICTS", "=" * 10)
        for file in f2_conflicts:
            print(f"FILE: {file}, CONFLICT:{f2_conflicts[file]}")
    if len(diff_conflicts) > 0:
        conflicts_found = True
        print("=" * 10, "DIFF CONFLICTS", "=" * 10)
        for file in diff_conflicts:
            print(file)
    # Exiting one tells PyTest we have conflicts
    if conflicts_found:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
