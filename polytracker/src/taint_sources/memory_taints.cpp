#include "polytracker/taint_sources.h"
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

  // TODO (hbrodin): This is incorrect. There is not new_size bytes available
  // (typically) but for now, lets just hope that the user of returned memory
  // clears it (no undefined read). This might actually cause a read oob if at
  // the end of shadow memory... Need to track all allocation sizes to only copy
  // the amount of memory avail in the old allocation.
  //
  // Make a copy of shadow memory/labels, in case we do actually move it
  // This could be a lot faster if we used the shadow_for function and did a
  // straight copy...
  std::vector<dfsan_label> shadow;
  auto oldptr = reinterpret_cast<char *>(ptr);
  if (oldptr != nullptr && new_size > 0) {
    shadow.reserve(new_size);
    std::transform(oldptr, oldptr + new_size, std::back_inserter(shadow),
                   [](char &v) { return dfsan_read_label(&v, sizeof(v)); });
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
