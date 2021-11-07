


OPTION(ENABLE_SANITIZERS "Enable asan,ubsan" TRUE)

set(GIGAFUNC_DEBUG_OPTIONS -g -O0 $<$<BOOL:${ENABLE_SANITIZERS}>:-fsanitize=address,undefined>)
set(GIGAFUNC_RELEASE_OPTIONS -g -O3  $<$<BOOL:${ENABLE_SANITIZERS}>:-fsanitize=address,undefined>)

add_compile_options(
                    "$<$<CONFIG:Debug>:${GIGAFUNC_DEBUG_OPTIONS}>"
                    "$<$<CONFIG:Release>:${GIGAFUNC_RELEASE_OPTIONS}>")
add_link_options(
                    "$<$<CONFIG:Debug>:${GIGAFUNC_DEBUG_OPTIONS}>"
                    "$<$<CONFIG:Release>:${GIGAFUNC_RELEASE_OPTIONS}>")

add_subdirectory(pass)
add_subdirectory(gfrt)
add_subdirectory(traceio)
add_subdirectory(gfanalyze)
# TODO: Add option for building with tests
enable_testing()
add_subdirectory(test)