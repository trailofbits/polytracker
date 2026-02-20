#include "polytracker/taint_sources.h"

// __dfsw_strcat
EXT_C_FUNC char *__dfsw_strcat(char *dest, char *src, dfsan_label dest_label,
                               dfsan_label src_label, dfsan_label *ret_label) {
  size_t curr_offset = strlen(dest);
  char *ret_val = strcat(dest, src);
  dfsan_set_label(src_label, dest + curr_offset, strlen(src));
  *ret_label = dest_label;
  return ret_val;
}
