project(polytracker LANGUAGES C CXX ASM)

include_directories(include)
set(POLYTRACK_BIN_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/bin")
set(POLYTRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/lib")
set(POLYTRACK_TRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/track")
set(POLYTRACK_RULE_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/abi_lists")
set(POLYTRACK_TESTS_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/tests")
set(POLYTRACK_PASS_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/pass")

add_subdirectory(src)
install(DIRECTORY "./abi_lists" DESTINATION ${POLYTRACK_CXX_DIR})

install(PROGRAMS "scripts/polybuild.py" DESTINATION ${POLYTRACK_BIN_DIR} RENAME "polybuild")
install(PROGRAMS "scripts/polybuild.py" DESTINATION ${POLYTRACK_BIN_DIR} RENAME "polybuild++")

macro(install_symlink filepath sympath)
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${filepath} ${sympath})")
    install(CODE "message(\"-- Created symlink: ${sympath} -> ${filepath}\")")
endmacro(install_symlink)

install(DIRECTORY DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
install_symlink(../share/polytracker/bin/polybuild ${CMAKE_INSTALL_PREFIX}/bin/polybuild)
install_symlink(../share/polytracker/bin/polybuild ${CMAKE_INSTALL_PREFIX}/bin/polybuild++)
