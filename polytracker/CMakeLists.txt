project(polytracker LANGUAGES C CXX ASM)

include_directories(include)

set(POLYTRACK_BIN_DIR "${CMAKE_INSTALL_PREFIX}/polytracker")
set(POLYTRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/lib")
set(POLYTRACK_TRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/track")
set(POLYTRACK_RULE_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/abi_lists")
set(POLYTRACK_TESTS_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/tests")
set(POLYTRACK_PASS_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/pass")
set(POLYTRACK_CXX_DIR "${CMAKE_INSTALL_PREFIX}/polytracker/")

add_subdirectory(src)
add_subdirectory(custom_abi)
install(DIRECTORY "./cxx_libs" DESTINATION ${POLYTRACK_CXX_DIR})
