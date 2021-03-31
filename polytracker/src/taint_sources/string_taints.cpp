#include <sanitizer/dfsan_interface.h>
#include "polytracker/taint.h"
#include <string.h>

#define BYTE 1
#define EXT_C_FUNC extern "C" __attribute__((visibility("default")))
#define EXT_CXX_FUNC extern __attribute__((visibility("default")))
#define PPCAT_NX(A, B) A##B
#define PPCAT(A, B) PPCAT_NX(A, B)

EXT_C_FUNC 
char* __dfsw_strcat(char * dest, char * src, dfsan_label dest_label, dfsan_label src_label, dfsan_label *ret_label) {
    int curr_offset = strlen(dest) - 1;
    char * ret_val = strcat(dest, src);
    dfsan_set_label(src_label, dest + curr_offset, strlen(dest) - curr_offset);
    *ret_label = dest_label;
    return ret_val;
}

