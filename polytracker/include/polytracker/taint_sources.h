#ifndef __TAINT_SOURCES_H
#define __TAINT_SOURCES_H

#include <sanitizer/dfsan_interface.h>
#include "polytracker/taint.h"
#include <string.h>

#define BYTE 1
#define EXT_C_FUNC extern "C" __attribute__((visibility("default")))
#define EXT_CXX_FUNC extern __attribute__((visibility("default")))
#define PPCAT_NX(A, B) A##B
#define PPCAT(A, B) PPCAT_NX(A, B)
typedef PPCAT(PPCAT(uint, DFSAN_LABEL_BITS), _t) uint_dfsan_label_t;


#endif