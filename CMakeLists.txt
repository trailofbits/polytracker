cmake_minimum_required(VERSION 3.5.1)

project(TAPP)

# If there is no explicit -DCMAKE_INSTALL_PREFIX=DIR setting given,
# then install underneath the build directory
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set (CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR} CACHE PATH "default install path" FORCE)
endif()

set(POLYTRACK_BIN_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/bin")
set(POLYTRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/lib")
set(POLYTRACK_TRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/track")
set(POLYTRACK_RULE_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/abi_lists")
set(POLYTRACK_TESTS_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/tests")
set(POLYTRACK_PASS_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/pass")
set(POLYTRACK_CXX_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker")

add_subdirectory(polytracker)
