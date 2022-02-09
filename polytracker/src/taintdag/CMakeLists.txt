
set(CMAKE_CXX_STANDARD 17)
add_subdirectory(test)

add_library(taintdag STATIC encoding.cpp fdmapping.cpp output.cpp print.cpp)