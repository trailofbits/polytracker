set(CMAKE_POSITION_INDEPENDENT_CODE ON) 
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

add_library(TaintSources STATIC taint_sources.cpp)
install (TARGETS TaintSources DESTINATION ${POLYTRACK_LIB_DIR}) 
