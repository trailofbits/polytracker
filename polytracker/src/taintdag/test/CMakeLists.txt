set(CMAKE_CXX_STANDARD 17)

Include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.7
)

FetchContent_MakeAvailable(Catch2)


list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/contrib)
include(CTest)
include(Catch)

add_executable(tests main.cpp taintdag.cpp output.cpp encoding.cpp fdmapping.cpp union.cpp)
target_link_libraries(tests PRIVATE Catch2::Catch2 taintdag)

catch_discover_tests(tests)