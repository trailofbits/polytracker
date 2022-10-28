set(CMAKE_CXX_FLAGS
    "-stdlib=libc++ -static -I${POLYTRACK_CXX_INCLUDE} -fno-rtti -D_GNU_SOURCE -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D__STDC_LIMIT_MACROS -Wall -Werror -g -O3"
)

set(CMAKE_EXE_LINKER_FLAGS
    "-stdlib=libc++ -L/polytracker_clang/lib -L${POLYTRACK_CXX_LIB} -pthread")

set(TAINTDAG_UNITTEST tests-taintdag)

add_executable(
  ${TAINTDAG_UNITTEST}
  main.cpp
  tdag.cpp
  taintdag.cpp
  encoding.cpp
  fnmapping.cpp
  union.cpp
  labeldeq.cpp)

target_include_directories(${TAINTDAG_UNITTEST}
                           PUBLIC ${CMAKE_SOURCE_DIR}/polytracker/include)

target_link_libraries(${TAINTDAG_UNITTEST} Polytracker Catch2::Catch2
                      spdlog::spdlog_header_only)

add_test(
  NAME test_${TAINTDAG_UNITTEST}
  COMMAND "$<TARGET_FILE:${TAINTDAG_UNITTEST}>"
  WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
