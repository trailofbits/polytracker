#!/usr/bin/env bash
# Temporary formatting script to enforce some code style/standards 

set -e

# Clang-format to auto format the relevant parts of the C++ code base
# In CI this runs against the third_party clang_format checker 
# Note that we are using clang-format 10 locally and in CI 
clang-format -i src/**/*.cpp
clang-format -i include/**/*.h