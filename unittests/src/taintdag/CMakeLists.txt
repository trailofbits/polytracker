set(TAINTDAG_UNITTEST tests-taintdag)

add_executable(
  ${TAINTDAG_UNITTEST}
  main.cpp
  tdag.cpp
  taintdag.cpp
  bitmap_section.cpp
  encoding.cpp
  fnmapping.cpp
  fntrace.cpp
  union.cpp
  labeldeq.cpp
  stream_offset.cpp)

target_include_directories(${TAINTDAG_UNITTEST}
                           PRIVATE ${CMAKE_SOURCE_DIR}/polytracker/include)

target_include_directories(${TAINTDAG_UNITTEST}
                           PRIVATE ${CXX_LIB_PATH}/include/c++/v1)

target_compile_options(${TAINTDAG_UNITTEST} PRIVATE -stdlib=libc++
                                                    -Wall -Werror)
target_link_libraries(${TAINTDAG_UNITTEST} Polytracker Catch2::Catch2
                      spdlog::spdlog_header_only ${CXX_LIB_PATH}/lib/libc++.a ${CXX_LIB_PATH}/lib/libc++abi.a)

add_test(
  NAME test_${TAINTDAG_UNITTEST}
  COMMAND "$<TARGET_FILE:${TAINTDAG_UNITTEST}>"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
