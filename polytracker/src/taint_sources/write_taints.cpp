#include "polytracker/dfsan_types.h"
#include "polytracker/early_construct.h"
#include "polytracker/taint_sources.h"
#include "taintdag/polytracker.h"
#include <iostream>
#include <sanitizer/dfsan_interface.h>
#include <sys/socket.h>
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
EARLY_CONSTRUCT_EXTERN_GETTER(taintdag::PolyTracker, polytracker_tdag);

namespace {

// Records the taint operation on fd
//
// Will only record writes where `length.valid()`. That is when at least one
// byte was written.
// `fd` is the file descriptor that was written to
// `offset` is the offset writes started from
// `length` is the amount of data written
// `buffer` is the source buffer written to `fd`
void impl_taint_sink(int fd, util::Offset offset, util::Length length,
                     void *buffer) {
  if (length.valid()) {
    get_polytracker_tdag().taint_sink(fd, offset, buffer, *length.value());
  }
}

// Implementation wrapper for write/send-style functions
//
// `ret_label` is the return value label, will be cleared
// `fd` file descriptor to use
// `buffer` is the buffer written from
// `write_func` is the function that performs the operation (e.g. `write`)
// `write_func_args` are the arguments to pass to `write_func`
template <typename F, typename... Args>
ssize_t impl_write_send(dfsan_label &ret_label, int fd, void *buffer,
                        F &&write_func, Args... write_func_args) {
  auto offset = util::Offset::from_fd(fd);
  auto retval = write_func(write_func_args...);
  impl_taint_sink(fd, offset, util::Length::from_returned_size(retval), buffer);
  ret_label = 0;
  return retval;
}
} // namespace

EXT_C_FUNC ssize_t __dfsw_write(int fd, void *buf, size_t count,
                                dfsan_label fd_label, dfsan_label buff_label,
                                dfsan_label count_label,
                                dfsan_label *ret_label) {
  return impl_write_send(*ret_label, fd, buf, write, fd, buf, count);
}

EXT_C_FUNC size_t __dfsw_fwrite(void *buf, size_t size, size_t count,
                                FILE *stream, dfsan_label buff_label,
                                dfsan_label size_label, dfsan_label count_label,
                                dfsan_label stream_label,
                                dfsan_label *ret_label) {
  auto offset = util::Offset::from_file(stream);
  auto write_count = fwrite(buf, size, count, stream);
  auto length = util::Length::from_returned_size_count(size, write_count);
  impl_taint_sink(fileno(stream), offset, length, buf);
  *ret_label = 0;
  return write_count;
}

EXT_C_FUNC int __dfsw_putc(int ch, FILE *stream, dfsan_label ch_label,
                           dfsan_label stream_label, dfsan_label *ret_label) {
  auto offset = util::Offset::from_file(stream);
  auto ret = fputc(ch, stream);
  if (ret == ch) {
    get_polytracker_tdag().taint_sink(fileno(stream), offset, ch_label,
                                      sizeof(char));
  }
  *ret_label = 0;
  return ret;
}

EXT_C_FUNC int __dfsw_fputc(int ch, FILE *stream, dfsan_label ch_label,
                            dfsan_label stream_label, dfsan_label *ret_label) {
  return __dfsw_putc(ch, stream, ch_label, stream_label, ret_label);
}

// Socket functions
EXT_C_FUNC ssize_t __dfsw_send(int socket, void *buffer, size_t length,
                               int flags, dfsan_label socket_label,
                               dfsan_label buffer_label,
                               dfsan_label length_label,
                               dfsan_label flags_label,
                               dfsan_label *ret_label) {

  return impl_write_send(*ret_label, socket, buffer, send, socket, buffer,
                         length, flags);
}
