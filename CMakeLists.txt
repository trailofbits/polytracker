cmake_minimum_required(VERSION 3.5.1)

project(TAPP)

# If there is no explicit -DCMAKE_INSTALL_PREFIX=DIR setting given,
# then install underneath the build directory
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set (CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/bin CACHE PATH "default install path" FORCE)
endif()
add_subdirectory(polytracker)
