set (TESTS
	test_dfsan.cc
	)

add_executable(test_all ${TESTS})

install (TARGETS test_all DESTINATION ${POLYTRACK_TESTS_DIR})


