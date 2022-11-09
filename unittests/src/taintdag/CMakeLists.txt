set(TAINTDAG_UNITTEST tests-taintdag)

add_executable(
  ${TAINTDAG_UNITTEST}
  main.cpp
  bitmap_section.cpp
  encoding.cpp
  fnmapping.cpp
  union.cpp
  labeldeq.cpp
  stream_offset.cpp
  tdag.cpp)

target_include_directories(
  ${TAINTDAG_UNITTEST} PUBLIC ${CMAKE_SOURCE_DIR}/polytracker/include
                              ${POLYTRACKER_CXX_INCLUDE})

target_compile_options(${TAINTDAG_UNITTEST} PRIVATE -fno-rtti -Wall -Werror
                                                    -stdlib=libc++)

target_link_options(${TAINTDAG_UNITTEST} PRIVATE -stdlib=libc++)
target_link_directories(${TAINTDAG_UNITTEST} PRIVATE ${POLYTRACKER_CXX_LIB})
target_link_libraries(${TAINTDAG_UNITTEST} Polytracker Catch2::Catch2
                      spdlog::spdlog_header_only)

add_test(
  NAME test_${TAINTDAG_UNITTEST}
  COMMAND "$<TARGET_FILE:${TAINTDAG_UNITTEST}>"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
