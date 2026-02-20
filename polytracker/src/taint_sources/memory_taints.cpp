#include "polytracker/taint_sources.h"
#include <malloc.h>
#include <vector>

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

  std::vector<dfsan_label> shadow;
  auto oldptr = reinterpret_cast<char *>(ptr);
  if (oldptr != nullptr && new_size > 0) {
    size_t old_size = malloc_usable_size(ptr);
    size_t copy_size = std::min(new_size, old_size);
    shadow.reserve(copy_size);
    std::transform(oldptr, oldptr + copy_size,
                   std::back_inserter(shadow),
                   [](char &v) {
                     return dfsan_read_label(&v, sizeof(v));
                   });
  }

  void *new_mem = realloc(ptr, new_size);
  if (new_mem != oldptr) {
    for (size_t i = 0; i < shadow.size(); i++) {
      dfsan_set_label(shadow[i], reinterpret_cast<char *>(new_mem) + i,
                      sizeof(char));
    }
  }
  *ret_label = 0;
  return new_mem;
}

EXT_C_FUNC void __dfsw_free(void *mem, dfsan_label mem_label) { free(mem); }
