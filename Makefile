# This is intentionally a very simple top-level Makefile, just to drive the
# semi-complicated CMake build process.

# This Makefile provides a few top-level targets
.PHONY: install clean check

CC       := clang
CXX      := clang++
CFLAGS   := -DSANITIZER_DEBUG=1 -Wall -Wextra -Wno-unused-parameter
CXXFLAGS := $(CFLAGS)

install: .cmake_init
	$(MAKE) -C build install

.cmake_init:
	mkdir -p build
	cd build && CC="$(CC)" CXX="$(CXX)" CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=1 -DCMAKE_BUILD_TYPE=Debug ../
	touch $@

clean:
	rm -rf build .cmake_init

check: install
	env PATH="$$PATH:$$PWD/build/bin/polytracker" polytracker/test/test-polytracker
