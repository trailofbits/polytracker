cmake_minimum_required(VERSION 3.5.1)

#list(APPEND CMAKE_PREFIX_PATH ${LLVM_7_PATH})
#find_package(LLVM 7.1 CONFIG)
find_package(LLVM 13 CONFIG)

if (LLVM_FOUND)
  message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
  message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
  message(STATUS "LLVM_VERSION_PATCH: ${LLVM_VERSION_PATCH}")
else()
  message(FATAL_ERROR "You need LLVM >=10 to build this (found LLVM ${LLVM_VERSION_MAJOR}).")
endif()

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
#if (NOT TARGET LLVMPassConfig)
  add_library(LLVMPassConfig INTERFACE IMPORTED)
  set_target_properties(LLVMPassConfig PROPERTIES
    INTERFACE_COMPILE_OPTIONS "-fno-rtti" #-fpic
    INTERFACE_INCLUDE_DIRECTORIES "${LLVM_INCLUDE_DIRS}"
    INTERFACE_LINK_DIRECTORIES "${LLVM_LIBRARY_DIRS}"
    INTERFACE_COMPILE_DEFINITIONS "LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR};LLVM_VERSION_MINOR=${LLVM_VERSION_MINOR}"
    # INTERFACE_LINK_OPTIONS "-Wl,-znodelete"
    )
#endif()
#list(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

#set(LLVM_RUNTIME_OUTPUT_INTDIR ${POLYTRACK_PASS_DIR})
#set(LLVM_LIBRARY_OUTPUT_INTDIR ${POLYTRACK_PASS_DIR})
#add_definitions(${LLVM_DEFINITIONS})
#include_directories(${LLVM_INCLUDE_DIRS})
#link_directories(${LLVM_LIBRARY_DIRS})
#include(HandleLLVMOptions) 
#include(AddLLVM)


#set(LLVM_RUNTIME_OUTPUT_INTDIR "${CMAKE_BINARY_DIR}/bin/${CMAKE_CFG_INT_DIR}")
#set(LLVM_LIBRARY_OUTPUT_INTDIR "${CMAKE_BINARY_DIR}/lib/${CMAKE_CFG_INT_DIR}")

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_MODULE_LINKER_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-znodelete")
if(APPLE)
  # User teor2345 reports that this is required to make things work on MacOS X.
  set (CMAKE_MODULE_LINK_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-flat_namespace -Wl,-undefined,suppress")
endif(APPLE)

#add_llvm_library(LLVMShit DataFlowSanitizer.cpp BBSplittingPass.cpp)
add_library(PolytrackerPass SHARED PolytrackerPass.cpp BBSplittingPass.cpp)
target_link_libraries(PolytrackerPass LLVMPassConfig)
install (TARGETS PolytrackerPass DESTINATION ${POLYTRACK_PASS_DIR})
#target_link_libraries(LLVMtest LLVMPassConfig)
#install (TARGETS LLVMtest DESTINATION ${POLYTRACK_PASS_DIR})
