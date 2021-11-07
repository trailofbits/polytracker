cmake_minimum_required(VERSION 3.7.2)

project(GIGAFUNCTION)

set(GIGAFUNCTION_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include")

set(CMAKE_PREFIX_PATH /usr/local/opt/llvm)
set(CMAKE_EXPORT_COMPILE_COMMANDS TRUE)

set(CMAKE_CXX_STANDARD 17)

# If you are on MacOS using homebrew, you typically need to invoke CMake using
# Aarch64
# cmake -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/llvm -DCMAKE_CXX_COMPILER=/opt/homebrew/opt/llvm/bin/clang++ -DCMAKE_C_COMPILER=/opt/homebrew/opt/llvm/bin/clang -DCMAKE_EXPORT_COMPILE_COMMANDS=TRUE ..
# X86
# cmake -DCMAKE_PREFIX_PATH=/usr/local/opt/llvm -DCMAKE_CXX_COMPILER=/usr/local/opt/llvm/bin/clang++ -DCMAKE_C_COMPILER=/usr/local/opt/llvm/bin/clang -DCMAKE_EXPORT_COMPILE_COMMANDS=TRUE ..

include_directories(${GIGAFUNCTION_INCLUDE_DIR})
add_compile_options(-Wall -Wextra -pedantic -Werror -stdlib=libc++)

add_subdirectory(src)



# TODO (hbrodin): Add proper configuration Debug/Release and ensure correct build flags e.g. -O3 for release