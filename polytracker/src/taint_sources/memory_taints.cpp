#include "polytracker/taint_sources.h"

EXT_C_FUNC void *__dfsw_malloc(size_t size, dfsan_label size_label,
                               dfsan_label *ret_label) {
  void *new_mem = malloc(size);
  *ret_label = 0;
  return new_mem;
}
// TODO (Carson) Capture heap allocations to replicate TIFF bug
EXT_C_FUNC void *__dfsw_realloc(void *ptr, size_t new_size,
                                dfsan_label ptr_label, dfsan_label size_label,
                                dfsan_label *ret_label) {

  void *new_mem = realloc(ptr, new_size);
  if (new_mem != NULL && new_mem != ptr) {
  }
  *ret_label = 0;
  return new_mem;
}

EXT_C_FUNC void __dfsw_free(void *mem, dfsan_label mem_label) { free(mem); }
