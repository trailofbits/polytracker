set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -g")

set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_CXX_LINK_FLAGS} -Wl,-znodelete")
if(APPLE)
  # User teor2345 reports that this is required to make things work on MacOS X.
  set(CMAKE_MODULE_LINK_FLAGS
      "${CMAKE_CXX_LINK_FLAGS} -Wl,-flat_namespace -Wl,-undefined,suppress")
endif(APPLE)

add_library(PolytrackerPass SHARED taint_tracking.cpp polytracker_pass.cpp bb_splitting_pass.cpp)
target_link_libraries(
  PolytrackerPass
  PUBLIC LLVMPassConfig
  PRIVATE indicators spdlog::spdlog_header_only)
install(TARGETS PolytrackerPass DESTINATION ${POLYTRACK_PASS_DIR})
