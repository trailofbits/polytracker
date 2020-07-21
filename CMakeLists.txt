cmake_minimum_required(VERSION 3.5.1)

project(TAPP)

# If there is no explicit -DCMAKE_INSTALL_PREFIX=DIR setting given,
# then install underneath the build directory
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set (CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/bin CACHE PATH "default install path" FORCE)
endif()

set(POLYTRACK_BIN_DIR "${CMAKE_INSTALL_PREFIX}/polytracker")
set(POLYTRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/lib")
set(POLYTRACK_TRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/track")
set(POLYTRACK_RULE_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/abi_lists")
set(POLYTRACK_TESTS_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/tests")
set(POLYTRACK_PASS_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/pass")
set(POLYTRACK_CXX_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/")

add_subdirectory(polytracker)
