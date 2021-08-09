#include "polytracker/dfsan_types.h"
#include "polytracker/logging.h"
#include "polytracker/output.h"
#include <iostream>
#include <sanitizer/dfsan_interface.h>
#include <sys/types.h>
#include <unistd.h>

/*
inline dfsan_label *shadow_for(void *ptr) {
  //Was 1, the shift should be DFSAN_LABEL_BITS/16
  return (dfsan_label *) ((((uptr) ptr) & ShadowMask()) << 2);
}

inline const dfsan_label *shadow_for(const void *ptr) {
  return shadow_for(const_cast<void *>(ptr));
}

ShadowMask() = static const uptr kShadowMask = ~0x700000000000;

*/
#define EXT_C_FUNC extern "C" __attribute__((visibility("default")))
EXT_C_FUNC ssize_t __dfsw_write(int fd, void *buf, size_t count,
                                dfsan_label fd_label, dfsan_label buff_label,
                                dfsan_label count_label,
                                dfsan_label *ret_label) {
  // We don't really care about the buf label exactly, what we want is for
  // every tainted byte we are writing, store the output offset taint pair.
  for (auto i = 0; i < count; i++) {
    auto taint_label = dfsan_read_label(buf, sizeof(char));
    std::cout << "Taint for: " << i << " is: " << taint_label << std::endl;
  }
  *ret_label = 0;
  return write(fd, buf, count);
}
