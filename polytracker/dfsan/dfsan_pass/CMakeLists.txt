cmake_minimum_required(VERSION 3.5.1)

list(APPEND CMAKE_PREFIX_PATH ${LLVM_7_PATH})
find_package(LLVM REQUIRED CONFIG)

if (LLVM_FOUND)
  message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
  message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
  message(STATUS "LLVM_VERSION_PATCH: ${LLVM_VERSION_PATCH}")
else()
  message(FATAL_ERROR "LLVM not found")
endif()

if (NOT (LLVM_VERSION_MAJOR EQUAL 7))
    message(FATAL_ERROR "You need LLVM 7 to build this (found LLVM ${LLVM_VERSION_MAJOR}). "
                        "If this is not what you expect, perhaps you need to set the LLVM_7_PATH CMake variable. "
                        "Alternatively, adjust your PATH so that LLVM 7 binaries appear first.")
endif()

if (NOT TARGET LLVMPassConfig)
  add_library(LLVMPassConfig INTERFACE IMPORTED)
  set_target_properties(LLVMPassConfig PROPERTIES
    INTERFACE_COMPILE_OPTIONS "-fno-rtti" #-fpic
    INTERFACE_INCLUDE_DIRECTORIES "${LLVM_INCLUDE_DIRS}"
    INTERFACE_LINK_DIRECTORIES "${LLVM_LIBRARY_DIRS}"
    INTERFACE_COMPILE_DEFINITIONS "LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR};LLVM_VERSION_MINOR=${LLVM_VERSION_MINOR}"
    # INTERFACE_LINK_OPTIONS "-Wl,-znodelete"
    )
endif()

set (CMAKE_CXX_STANDARD 11)
set (CMAKE_MODULE_LINKER_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-znodelete")
if(APPLE)
  # User teor2345 reports that this is required to make things work on MacOS X.
  set (CMAKE_MODULE_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-flat_namespace -Wl,-undefined,suppress")
endif(APPLE)

add_library(DataFlowSanitizerPass MODULE DataFlowSanitizer.cpp)
target_link_libraries(DataFlowSanitizerPass LLVMPassConfig)

install (TARGETS DataFlowSanitizerPass DESTINATION ${POLYTRACK_PASS_DIR})
