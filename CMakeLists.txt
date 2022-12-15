cmake_minimum_required(VERSION 3.5.1)

project(TAPP)

# If there is no explicit -DCMAKE_INSTALL_PREFIX=DIR setting given,
# then install underneath the build directory
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set (CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR} CACHE PATH "default install path" FORCE)
endif()
if (NOT DEFINED CXX_LIB_PATH)
    message(FATAL_ERROR "Can't find Polytrackers libcxx, please set -DCXX_LIB_PATH")
endif()

set(POLYTRACKER_CXX_INCLUDE "${CXX_LIB_PATH}/include/c++/v1")
set(POLYTRACKER_CXX_LIB "${CXX_LIB_PATH}/lib")

set(POLYTRACKER_BIN_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/bin")
set(POLYTRACKER_LIB_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/lib")
set(POLYTRACKER_TRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/track")
set(POLYTRACKER_RULE_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/abi_lists")
set(POLYTRACKER_TESTS_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/tests")
set(POLYTRACKER_PASS_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/pass")
set(POLYTRACKER_CXX_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker")

if(NOT EXISTS "${PROJECT_SOURCE_DIR}/third_party/indicators/CMakeLists.txt")
    message(FATAL_ERROR "git submodule update --init --recursive must be run first to checkout submodules")
endif()

set(CMAKE_CXX_STANDARD 20)

add_subdirectory(third_party/Catch2)
list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/third_party/Catch2/contrib")
add_subdirectory(third_party/indicators)
set(SPDLOG_NO_EXCEPTIONS TRUE)
add_subdirectory(third_party/spdlog)

add_subdirectory(polytracker)

enable_testing()
add_subdirectory(unittests/src/taintdag)
