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

# Unit tests
add_executable(tests main.cpp spsc_buffer_test.cpp trace_reader_writer_test.cpp varint_test.cpp serialization_test.cpp)
target_link_libraries(tests PRIVATE Catch2::Catch2 traceio)
catch_discover_tests(tests)


# Stress testing using threads
add_executable(gfrt_tests gfrt_test.cpp)
target_link_libraries(gfrt_tests gigafuncruntime traceio)