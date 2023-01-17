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
                           PUBLIC ${CMAKE_SOURCE_DIR}/polytracker/include)

target_compile_options(${TAINTDAG_UNITTEST} PRIVATE -fno-rtti -Wall -Werror)

target_link_libraries(${TAINTDAG_UNITTEST} Polytracker Catch2::Catch2
                      spdlog::spdlog_header_only)

add_test(
  NAME test_${TAINTDAG_UNITTEST}
  COMMAND "$<TARGET_FILE:${TAINTDAG_UNITTEST}>"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
