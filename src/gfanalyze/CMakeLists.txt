# Ref https://llvm.org/docs/CMake.html

find_package(LLVM REQUIRED CONFIG)
include_directories(${LLVM_INCLUDE_DIRS})
separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})
add_definitions(${LLVM_DEFINITIONS_LIST})

# Now build our tools
add_executable(gfanalyze gfanalyze.cpp)

# Find the libraries that correspond to the LLVM components
# that we wish to use
llvm_map_components_to_libnames(llvm_libs support core irreader)

# Link against LLVM libraries
target_link_libraries(gfanalyze ${llvm_libs} traceio)


#find_package(LLVM REQUIRED CONFIG)
#include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
#add_definitions(${LLVM_DEFINITIONS})
#message(WARNING ${LLVM_DEFINITIONS})

#add_executable(gfanalyze gfanalyze.cpp)