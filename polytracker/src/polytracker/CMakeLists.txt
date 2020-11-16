set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# TODO Turn back on Wall Werror
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fPIC -frtti -Wno-c++98-compat-pedantic -Wno-undef -Wno-unused-parameter -Wno-reserved-id-macro -Wno-missing-noreturn -Wno-c++98-compat -Wno-vexing-parse -Wno-shadow-field-in-constructor -Wno-ignored-qualifiers")

#add_subdirectory(/fmt "${CMAKE_CURRENT_BINARY_DIR}/fmt")

#if (fmt_FOUND)
#  message(STATUS "libfmt found!")
#else()
# 	message(FATAL_ERROR "libfmt not found")
#endif()

add_library(Polytracker STATIC main.cpp logging.cpp taint.cpp output.cpp tracing.cpp)
target_link_libraries(Polytracker PRIVATE fmt::fmt-header-only)
install (TARGETS Polytracker DESTINATION ${POLYTRACK_LIB_DIR})
