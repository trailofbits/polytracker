# Temporary formatting script to enforce some code style/standards 

# Clang-format to auto format the relevant parts of the C++ code base
# In CI this runs against the third_party clang_format checker 
# Note that we are using clang-format 10 locally and in CI 
clang-format -i polytracker/src/dfsan_sources/*.cpp
clang-format -i polytracker/src/dfsan_pass/*.cpp
clang-format -i polytracker/src/dfsan_rt/dfsan/*.cpp
clang-format -i polytracker/src/polytracker/*.cpp
clang-format -i polytracker/include/polyclang/*.h
clang-format -i polytracker/include/dfsan/*.h

# Black to auto format code, mypy for type checking
black polytracker tests --exclude '/(polytracker/src|polytracker/scripts)/'
mypy --ignore-missing-imports polytracker tests
