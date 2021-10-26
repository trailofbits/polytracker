find_package(LLVM REQUIRED CONFIG)

include_directories(SYSTEM ${LLVM_INCLUDE_DIRS})
add_definitions(${LLVM_DEFINITIONS})

add_library(InstrumentBasicBlocks SHARED instrument_basic_blocks.cpp)
add_library(MarkBasicBlocks SHARED mark_basic_blocks.cpp)

# From: https://github.com/banach-space/llvm-tutor/blob/main/HelloWorld/CMakeLists.txt
# Allow undefined symbols in shared objects on Darwin (this is the default
# behaviour on Linux)
target_link_libraries(InstrumentBasicBlocks
  "$<$<PLATFORM_ID:Darwin>:-undefined dynamic_lookup>")
target_link_libraries(MarkBasicBlocks
  "$<$<PLATFORM_ID:Darwin>:-undefined dynamic_lookup>")
  


# TODO (hbrodin): Drop this, just for convenience now.
# Compiling: /opt/homebrew/opt/llvm/bin/clang -O0 -Xclang -disable-O0-optnone -emit-llvm -c ../test.c 
# /opt/homebrew/opt/llvm/bin/opt -load-pass-plugin  src/pass/libTraceBasicBlocks.dylib --passes="basicblockstrace" -disable-output test.bc
# /opt/homebrew/opt/llvm/bin/opt -load-pass-plugin  src/pass/libTraceBasicBlocks.dylib --passes="basicblockstrace" -o out.bc test.bc
# /opt/homebrew/opt/llvm/bin/clang -g -o out ./src/librt/libgigafuncrt.a out.bc 