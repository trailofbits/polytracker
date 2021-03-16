add_subdirectory(passes)

# TODO Just do this here instead of in passes.
find_package(LLVM 13 CONFIG)

if (LLVM_FOUND)
  message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
  message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
  message(STATUS "LLVM_VERSION_PATCH: ${LLVM_VERSION_PATCH}")
else()
  message(FATAL_ERROR "You need LLVM >=10 to build this (found LLVM ${LLVM_VERSION_MAJOR}).")
endif()

set(POLY_DIR "polytracker")
set(TAINT_DIR "taint_sources")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror -stdlib=libc++ -static -I${POLYTRACK_CXX_INCLUDE} -O3 -g")
set(CMAKE_EXE_LINKER_FLAGS "-stdlib=libc++ -L${POLYTRACK_CXX_LIB} -Wl,--start-group,-lc++abi")

set(POLY_SOURCES
${POLY_DIR}/main.cpp 
${POLY_DIR}/logging.cpp 
${POLY_DIR}/taint.cpp
${POLY_DIR}/output.cpp 
# ${POLY_DIR}/tracing.cpp
${POLY_DIR}/tablegen.cpp 
${POLY_DIR}/polytracker.cpp
)

set (TAINT_SOURCES 
${TAINT_DIR}/taint_sources.cpp
)

add_library(Polytracker STATIC 
${POLY_SOURCES} 
${TAINT_SOURCES} 
)
target_link_libraries(Polytracker)
install (TARGETS Polytracker DESTINATION ${POLYTRACK_LIB_DIR})
