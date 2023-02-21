find_package(LLVM 13 CONFIG REQUIRED)

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})
add_library(LLVMPassConfig INTERFACE IMPORTED)
set_target_properties(
  LLVMPassConfig
  PROPERTIES
    INTERFACE_COMPILE_OPTIONS "-fno-rtti"
    INTERFACE_INCLUDE_DIRECTORIES "${LLVM_INCLUDE_DIRS}"
    INTERFACE_LINK_DIRECTORIES "${LLVM_LIBRARY_DIRS}"
    INTERFACE_COMPILE_DEFINITIONS
    "LLVM_VERSION_MAJOR=${LLVM_VERSION_MAJOR};LLVM_VERSION_MINOR=${LLVM_VERSION_MINOR}"
)

add_subdirectory(passes)

set(COMPILER_RT_SANITIZERS_TO_BUILD dfsan CACHE STRING "")
set(COMPILER_RT_BUILD_BUILTINS OFF CACHE BOOL "")
set(COMPILER_RT_BUILD_CRT OFF CACHE BOOL "")
set(COMPILER_RT_BUILD_PROFILE OFF CACHE BOOL "")
set(COMPILER_RT_BUILD_XRAY OFF CACHE BOOL "")
set(COMPILER_RT_BUILD_LIBFUZZER OFF CACHE BOOL "")
set(COMPILER_RT_BUILD_MEMPROF OFF CACHE BOOL "")

add_subdirectory(compiler-rt)

set(POLYTRACKER_DIR polytracker)
set(POLYTRACKER_SOURCES ${POLYTRACKER_DIR}/main.cpp
                        ${POLYTRACKER_DIR}/polytracker.cpp)

set(TAINT_DIR taint_sources)
set(TAINT_SOURCES
    ${TAINT_DIR}/taint_sources.cpp ${TAINT_DIR}/string_taints.cpp
    ${TAINT_DIR}/memory_taints.cpp ${TAINT_DIR}/write_taints.cpp
    ${TAINT_DIR}/argv.cpp)

set(TAINTDAG_DIR taintdag)
set(TAINTDAG_SOURCES
    ${TAINTDAG_DIR}/encoding.cpp
    ${TAINTDAG_DIR}/error.cpp
    ${TAINTDAG_DIR}/polytracker.cpp
    ${TAINTDAG_DIR}/print.cpp
    ${TAINTDAG_DIR}/fnmapping.cpp
    ${TAINTDAG_DIR}/fntrace.cpp
    ${TAINTDAG_DIR}/util.cpp)

add_library(Polytracker STATIC ${POLYTRACKER_SOURCES} ${TAINT_SOURCES}
                               ${TAINTDAG_SOURCES})

set(POLYTRACKER_COMPILE_OPTS -stdlib=libc++ -fno-exceptions -fno-rtti -Wall -Werror)

if(XRAY_ON)
  list(APPEND POLYTRACKER_COMPILE_OPTS -fxray-instrument
       -fxray-instruction-threshold=1)
endif()

target_include_directories(Polytracker PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/compiler-rt/include)
target_include_directories(Polytracker PRIVATE ${CXX_LIB_PATH}/include/c++/v1)
target_compile_options(Polytracker PRIVATE ${POLYTRACKER_COMPILE_OPTS})
target_link_directories(Polytracker PUBLIC ${CXX_LIB_PATH}/lib)
target_link_libraries(Polytracker LLVMPassConfig spdlog::spdlog_header_only c++)
set_property(TARGET Polytracker PROPERTY POSITION_INDEPENDENT_CODE ON)

install(TARGETS Polytracker DESTINATION ${POLYTRACKER_LIB_DIR})
