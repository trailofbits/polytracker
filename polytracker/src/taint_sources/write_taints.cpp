#include "polytracker/dfsan_types.h"
#include "polytracker/early_construct.h"
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
extern sqlite3 *output_db;
EARLY_CONSTRUCT_EXTERN_GETTER(fd_input_map_t, fd_input_map);

#define EXT_C_FUNC extern "C" __attribute__((visibility("default")))
EXT_C_FUNC ssize_t __dfsw_write(int fd, void *buf, size_t count,
                                dfsan_label fd_label, dfsan_label buff_label,
                                dfsan_label count_label,
                                dfsan_label *ret_label) {
  auto current_offset = lseek(fd, 0, SEEK_CUR);
  auto write_count = write(fd, buf, count);
  if (auto &input_id = get_fd_input_map()[fd]) {
    storeTaintedOutputChunk(output_db, input_id, current_offset,
                            current_offset + write_count);
    for (auto i = 0; i < write_count; i++) {
      auto taint_label = dfsan_read_label((char *)buf + i, sizeof(char));
      storeTaintedOutput(output_db, input_id, current_offset, taint_label);
      current_offset += 1;
    }
  }
  *ret_label = 0;
  return write_count;
}

#define EXT_C_FUNC extern "C" __attribute__((visibility("default")))
EXT_C_FUNC size_t __dfsw_fwrite(void *buf, size_t size, size_t count,
                                FILE *stream, dfsan_label buff_label,
                                dfsan_label size_label, dfsan_label count_label,
                                dfsan_label stream_label,
                                dfsan_label *ret_label) {
  auto current_offset = ftell(stream);
  auto write_count = fwrite(buf, size, count, stream);
  auto fd = fileno(stream);
  if (auto &input_id = get_fd_input_map()[fd]) {
    storeTaintedOutputChunk(output_db, input_id, current_offset,
                            current_offset + write_count);
    for (auto i = 0; i < write_count; i++) {
      auto taint_label = dfsan_read_label((char *)buf + i, sizeof(char));
      storeTaintedOutput(output_db, input_id, current_offset, taint_label);
      current_offset += 1;
    }
  }
  *ret_label = 0;
  return write_count;
}
