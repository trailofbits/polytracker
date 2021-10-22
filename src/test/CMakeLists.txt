Include(FetchContent)

FetchContent_Declare(
  Catch2
  GIT_REPOSITORY https://github.com/catchorg/Catch2.git
  GIT_TAG        v2.13.7
)

FetchContent_MakeAvailable(Catch2)

add_executable(tests main.cpp spsc_buffer_test.cpp)
target_link_libraries(tests PRIVATE Catch2::Catch2)


add_executable(librt_tests librt_test.cpp)
target_link_libraries(librt_tests gigafuncrt)