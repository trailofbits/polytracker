#ifndef POLYTRACKER_TAINT
#define POLYTRACKER_TAINT
#include "include/dfsan/dfsan_types.h"
//FIXME 
//[[nodiscard]] static dfsan_label createCanonicalLabel(int file_byte_offset, const char * name);
[[nodiscard]] dfsan_label createReturnLabel(int file_byte_offset, const char* name);
template<typename FileType> [[nodiscard]] bool isTracking(FileType fd);
template <typename FileType> [[nodiscard]] bool taintData(FileType fd, char * mem, int offset, int len);
void taintTargetRange(char* mem, int offset, int len, int byte_start, int byte_end, const char *name);
[[nodiscard]] dfsan_label createUnionLabel(dfsan_label& l1, dfsan_label& l2);
#endif