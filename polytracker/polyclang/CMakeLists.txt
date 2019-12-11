add_executable(PolyClang polyclang.cpp)
set_target_properties(PolyClang PROPERTIES OUTPUT_NAME "polyclang")

find_program(Clang "clang")
if(Clang STREQUAL "Clang-NOTFOUND")
    message(FATAL_ERROR "`clang` was not found; this program is required by polyclang")
endif()

find_program(Clang++ "clang++")
if(Clang++ STREQUAL "Clang++-NOTFOUND")
    message(FATAL_ERROR "`clang++` was not found; this program is required by polyclang")
endif()

# If we required CMake 3.14+, we could use the built-in `file(CREATE_LINK ...)` command.
add_custom_command(TARGET PolyClang POST_BUILD
    COMMAND ln -sf "polyclang" "polyclang++")

install (TARGETS PolyClang DESTINATION ${POLYTRACK_BIN_DIR})
install (FILES ${CMAKE_CURRENT_BINARY_DIR}/polyclang++ DESTINATION ${POLYTRACK_BIN_DIR})
