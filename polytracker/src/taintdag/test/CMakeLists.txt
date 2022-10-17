set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fexceptions")
set(CMAKE_EXE_LINKER_FLAGS
    "-stdlib=libc++ -L/polytracker_clang/lib -L${POLYTRACK_CXX_LIB} -pthread")

include(CTest)
include(Catch)

add_executable(
  tests
  main.cpp
  taintdag.cpp
  encoding.cpp
  fdmapping.cpp
  fnmapping.cpp
  union.cpp
  labeldeq.cpp)

target_link_libraries(tests PRIVATE Polytracker Catch2::Catch2
                                    spdlog::spdlog_header_only)

catch_discover_tests(tests)
