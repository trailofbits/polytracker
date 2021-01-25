add_subdirectory(passes)
add_subdirectory(dfsan_pass)

set(POLY_DIR "polytracker")
set(TAINT_DIR "dfsan_sources")
set(DFSAN_DIR "dfsan_rt/dfsan")
set(INTERCEPT_DIR "dfsan_rt/interception")
set(SAN_DIR "dfsan_rt/sanitizer_common")

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

set(INTERCEPTION_SOURCES
  ${INTERCEPT_DIR}/interception_linux.cc
  ${INTERCEPT_DIR}/interception_mac.cc
  ${INTERCEPT_DIR}/interception_win.cc
  #${INTERCEPT_DIR}/interception_type_test.cc
)

set(DFSAN_RTL_SOURCES
	${DFSAN_DIR}/dfsan.cpp
	${DFSAN_DIR}/dfsan_custom.cpp
	${DFSAN_DIR}/dfsan_interceptors.cpp
)
    
set(SANITIZER_SOURCES_NOTERMINATION
	${SAN_DIR}/sanitizer_allocator.cc
	${SAN_DIR}/sanitizer_common.cc
	${SAN_DIR}/sanitizer_deadlock_detector1.cc
	${SAN_DIR}/sanitizer_deadlock_detector2.cc
	${SAN_DIR}/sanitizer_errno.cc
	${SAN_DIR}/sanitizer_file.cc
	${SAN_DIR}/sanitizer_flags.cc
	${SAN_DIR}/sanitizer_flag_parser.cc
	${SAN_DIR}/sanitizer_fuchsia.cc
	${SAN_DIR}/sanitizer_libc.cc
	${SAN_DIR}/sanitizer_libignore.cc
	${SAN_DIR}/sanitizer_linux.cc
	${SAN_DIR}/sanitizer_linux_s390.cc
	${SAN_DIR}/sanitizer_mac.cc
	${SAN_DIR}/sanitizer_openbsd.cc
	${SAN_DIR}/sanitizer_persistent_allocator.cc
	${SAN_DIR}/sanitizer_platform_limits_linux.cc
	${SAN_DIR}/sanitizer_platform_limits_netbsd.cc
	${SAN_DIR}/sanitizer_platform_limits_openbsd.cc
	${SAN_DIR}/sanitizer_platform_limits_posix.cc
	${SAN_DIR}/sanitizer_platform_limits_solaris.cc
	${SAN_DIR}/sanitizer_posix.cc
	${SAN_DIR}/sanitizer_printf.cc
	${SAN_DIR}/sanitizer_procmaps_common.cc
	${SAN_DIR}/sanitizer_procmaps_bsd.cc
	${SAN_DIR}/sanitizer_procmaps_linux.cc
	${SAN_DIR}/sanitizer_procmaps_mac.cc
	${SAN_DIR}/sanitizer_procmaps_solaris.cc
	${SAN_DIR}/sanitizer_rtems.cc
	${SAN_DIR}/sanitizer_solaris.cc
	${SAN_DIR}/sanitizer_stoptheworld_mac.cc
	${SAN_DIR}/sanitizer_suppressions.cc
	${SAN_DIR}/sanitizer_tls_get_addr.cc
	${SAN_DIR}/sanitizer_thread_registry.cc
	${SAN_DIR}/sanitizer_win.cc)

set(SANITIZER_SOURCES
	${SANITIZER_SOURCES_NOTERMINATION} ${SAN_DIR}/sanitizer_termination.cc)

set(SANITIZER_LIBCDEP_SOURCES
	${SAN_DIR}/sanitizer_common_libcdep.cc
	${SAN_DIR}/sanitizer_allocator_checks.cc
	${SAN_DIR}/sanitizer_linux_libcdep.cc
	${SAN_DIR}/sanitizer_mac_libcdep.cc
	${SAN_DIR}/sanitizer_posix_libcdep.cc
	${SAN_DIR}/sanitizer_stoptheworld_linux_libcdep.cc)

set(SANITIZER_COVERAGE_SOURCES
	${SAN_DIR}/sancov_flags.cc
	${SAN_DIR}/sanitizer_coverage_fuchsia.cc
	${SAN_DIR}/sanitizer_coverage_libcdep_new.cc
	${SAN_DIR}/sanitizer_coverage_win_sections.cc)

set(SANITIZER_SYMBOLIZER_SOURCES
	${SAN_DIR}/sanitizer_allocator_report.cc
	${SAN_DIR}/sanitizer_stackdepot.cc
	${SAN_DIR}/sanitizer_stacktrace.cc
	${SAN_DIR}/sanitizer_stacktrace_libcdep.cc
	${SAN_DIR}/sanitizer_stacktrace_printer.cc
	${SAN_DIR}/sanitizer_stacktrace_sparc.cc
	${SAN_DIR}/sanitizer_symbolizer.cc
	${SAN_DIR}/sanitizer_symbolizer_libbacktrace.cc
	${SAN_DIR}/sanitizer_symbolizer_libcdep.cc
	${SAN_DIR}/sanitizer_symbolizer_mac.cc
	${SAN_DIR}/sanitizer_symbolizer_markup.cc
	${SAN_DIR}/sanitizer_symbolizer_posix_libcdep.cc
	${SAN_DIR}/sanitizer_symbolizer_report.cc
	${SAN_DIR}/sanitizer_symbolizer_win.cc
	${SAN_DIR}/sanitizer_unwind_linux_libcdep.cc
	${SAN_DIR}/sanitizer_unwind_win.cc
	)


add_library(Polytracker STATIC 
${POLY_SOURCES} 
${TAINT_SOURCES} 
${SANITIZER_SOURCES} 
${SANITIZER_LIBCDEP_SOURCES} 
${SANITIZER_COVERAGE_SOURCES} 
${SANITIZER_SYMBOLIZER_SOURCES}
)
target_link_libraries(Polytracker)
install (TARGETS Polytracker DESTINATION ${POLYTRACK_LIB_DIR})
