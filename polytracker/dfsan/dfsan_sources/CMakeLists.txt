set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include_directories("/polytracker/polytracker/dfsan/dfsan_rt/dfsan_private_headers/include/c++/v1")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -stdlib=libc++ -nostdinc++")

add_library(TaintSources STATIC taint_sources.cpp taint_management.cpp)
target_link_libraries(TaintSources "./libc++.a" "./libc++abi.a")
install (TARGETS TaintSources DESTINATION ${POLYTRACK_LIB_DIR}) 

