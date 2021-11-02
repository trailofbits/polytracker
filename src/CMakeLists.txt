set(CMAKE_CXX_STANDARD 17)
add_subdirectory(pass)
add_subdirectory(gfrt)
add_subdirectory(traceio)
add_subdirectory(gfanalyze)
# TODO: Add option for building with tests
enable_testing()
add_subdirectory(test)