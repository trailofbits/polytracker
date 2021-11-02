project(polytracker LANGUAGES C CXX ASM)

include_directories(include)
set(POLYTRACK_BIN_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/bin")
set(POLYTRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/lib")
set(POLYTRACK_TRACK_LIB_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/track")
set(POLYTRACK_RULE_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/abi_lists")
set(POLYTRACK_TESTS_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/tests")
set(POLYTRACK_PASS_DIR "${CMAKE_INSTALL_PREFIX}/share/polytracker/pass")

add_subdirectory(src)
install(DIRECTORY "./custom_abi" DESTINATION ${POLYTRACK_RULE_DIR})
add_subdirectory(custom_abi)

install(PROGRAMS "scripts/polybuild.py" DESTINATION ${POLYTRACK_BIN_DIR})
install(PROGRAMS "scripts/poly-link.py" DESTINATION ${POLYTRACK_BIN_DIR})

macro(install_symlink filepath sympath)
    install(CODE "execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${filepath} ${sympath})")
    install(CODE "message(\"-- Created symlink: ${sympath} -> ${filepath}\")")
endmacro(install_symlink)

install(DIRECTORY DESTINATION "${CMAKE_INSTALL_PREFIX}/bin")
install_symlink(../share/polytracker/bin/polybuild.py ${CMAKE_INSTALL_PREFIX}/bin/polybuild_script)
install_symlink(../share/polytracker/bin/polybuild.py ${CMAKE_INSTALL_PREFIX}/bin/polybuild_script++)
install_symlink(../share/polytracker/bin/poly-link.py ${CMAKE_INSTALL_PREFIX}/bin/poly-link)
