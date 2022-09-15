#ifndef __TAINT_SOURCES_H
#define __TAINT_SOURCES_H

#include <sanitizer/dfsan_interface.h>
#include <string.h>

#define BYTE 1
#define EXT_C_FUNC extern "C" __attribute__((visibility("default")))
#define EXT_CXX_FUNC extern __attribute__((visibility("default")))

namespace polytracker {
void taint_argv(int argc, char *argv[]);
}

#endif