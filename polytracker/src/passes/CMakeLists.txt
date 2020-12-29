cmake_minimum_required(VERSION 3.5.1)

list(APPEND CMAKE_PREFIX_PATH ${LLVM_7_PATH})
find_package(LLVM 7.1 CONFIG)
#find_package(LLVM 10 CONFIG)

if (LLVM_FOUND)
  message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
  message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
  message(STATUS "LLVM_VERSION_PATCH: ${LLVM_VERSION_PATCH}")
else()
	find_package(LLVM 7.0 CONFIG)
	if (LLVM_FOUND) 
  	message(STATUS "LLVM_VERSION_MAJOR: ${LLVM_VERSION_MAJOR}")
  	message(STATUS "LLVM_VERSION_MINOR: ${LLVM_VERSION_MINOR}")
  	message(STATUS "LLVM_VERSION_PATCH: ${LLVM_VERSION_PATCH}")
	else()
		message(FATAL_ERROR "LLVM not found")
	endif()
endif()

# was 7
if (NOT (LLVM_VERSION_MAJOR EQUAL 7))
    message(FATAL_ERROR "You need LLVM 7 to build this (found LLVM ${LLVM_VERSION_MAJOR}). "
                        "If this is not what you expect, perhaps you need to set the LLVM_7_PATH CMake variable. "
                        "Alternatively, adjust your PATH so that LLVM 7 binaries appear first.")
endif()

#add_definitions(${LLVM_DEFINITIONS})
#include_directories(${LLVM_INCLUDE_DIRS})
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
add_library(DataFlowSanitizerPass SHARED DataFlowSanitizer.cpp BBSplittingPass.cpp)
target_link_libraries(DataFlowSanitizerPass LLVMPassConfig)
install (TARGETS DataFlowSanitizerPass DESTINATION ${POLYTRACK_PASS_DIR})
#target_link_libraries(LLVMtest LLVMPassConfig)
#install (TARGETS LLVMtest DESTINATION ${POLYTRACK_PASS_DIR})
