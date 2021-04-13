#include "polytracker/taint_sources.h"

// TODO (Carson) associate allocations with tainted size

EXT_C_FUNC void *__dfsw_malloc(size_t size, dfsan_label size_label,
                               dfsan_label *ret_label) {
  void *new_mem = malloc(size);
  *ret_label = 0;
  return new_mem;
}

EXT_C_FUNC void *__dfsw_realloc(void *ptr, size_t new_size,
                                dfsan_label ptr_label, dfsan_label size_label,
                                dfsan_label *ret_label) {
  // TODO (Carson) Get label for each mem, but what is current size? Unknown
  void *new_mem = realloc(ptr, new_size);
  *ret_label = 0;
  return new_mem;
}

// DFSan has calloc implementation