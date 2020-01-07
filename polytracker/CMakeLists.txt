project(polytracker LANGUAGES C CXX ASM)

include_directories(dfsan)
include_directories(includes)

set(POLYTRACK_BIN_DIR "${CMAKE_INSTALL_PREFIX}/polytracker")
set(POLYTRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/lib")
set(POLYTRACK_RULE_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/abi_lists")
set(POLYTRACK_TEST_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/test")
set(POLYTRACK_PASS_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/pass")

add_subdirectory(polyclang)
add_subdirectory(custom_abi)
add_subdirectory(dfsan)
add_subdirectory(test)
