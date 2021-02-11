add_subdirectory(passes)

set(POLY_DIR "polytracker")
set(TAINT_DIR "taint_sources")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -stdlib=libc++ -static -I${POLYTRACK_CXX_INCLUDE}")
set(CMAKE_EXE_LINKER_FLAGS "-stdlib=libc++ -L${POLYTRACK_CXX_LIB} -Wl,--start-group,-lc++abi")

set(POLY_SOURCES
${POLY_DIR}/main.cpp 
${POLY_DIR}/logging.cpp 
${POLY_DIR}/taint.cpp
${POLY_DIR}/output.cpp 
${POLY_DIR}/tracing.cpp 
${POLY_DIR}/polytracker.cpp
)

set (TAINT_SOURCES 
${TAINT_DIR}/taint_sources.cpp
)

add_library(Polytracker STATIC 
${POLY_SOURCES} 
${TAINT_SOURCES} 
)
target_link_libraries(Polytracker)
install (TARGETS Polytracker DESTINATION ${POLYTRACK_LIB_DIR})
