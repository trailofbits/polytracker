include(CTest)
include(Catch)

add_executable(tests main.cpp taintdag.cpp output.cpp encoding.cpp fdmapping.cpp union.cpp labeldeq.cpp)
target_link_libraries(tests PRIVATE Catch2::Catch2 taintdag)

catch_discover_tests(tests)