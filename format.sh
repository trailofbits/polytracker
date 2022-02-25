#!/usr/bin/env bash
# Temporary formatting script to enforce some code style/standards 

set -e

# Clang-format to auto format the relevant parts of the C++ code base
# In CI this runs against the third_party clang_format checker 
# Note that we are using clang-format 10 locally and in CI 
clang-format -i polytracker/src/**/*.cpp
clang-format -i polytracker/include/**/*.{h,hpp}

# Black to auto format code, mypy for type checking
# Temporarily disabled because a bug in black is causing it not to reach a
# reformatting fixed point (every subsequent call causes reformatting)
# black polytracker tests --exclude '/(polytracker/src|polytracker/scripts)/'

flake8 polytracker tests --count --select=E9,F63,F7,F82 --show-source --statistics
flake8 polytracker tests --count --exit-zero --max-complexity=10 --max-line-length=127 --statistics

mypy --ignore-missing-imports polytracker tests
