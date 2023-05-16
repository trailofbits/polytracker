#include "polytracker/taint_sources.h"
#include "polytracker/early_construct.h"
#include "polytracker/polytracker.h"

#include "taintdag/error.h"
#include "taintdag/polytracker.h"
#include "taintdag/util.h"

#include <algorithm>
#include <arpa/inet.h>
#include <assert.h>
#include <fcntl.h>
#include <iostream>
#include <mutex>
#include <pthread.h>
#include <sanitizer/dfsan_interface.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <time.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <wchar.h>

#ifdef DEBUG_INFO
#include <iostream>
#endif

EARLY_CONSTRUCT_EXTERN_GETTER(taintdag::PolyTracker, polytracker_tdag);

using util::Length;
using util::Offset;

// To allow abort to somewhat gracefully finalize polytracker logging
extern void polytracker_end();

// To create some label functions
// Following the libc custom functions from custom.cc
namespace {

static int impl_open(const char *path, int oflags, dfsan_label path_label,
                     dfsan_label flag_label, dfsan_label *va_labels,
                     dfsan_label *ret_label, ...) {
  va_list args;
  va_start(args, ret_label);
  int fd = open(path, oflags, args);
  va_end(args);

  if (fd >= 0) {
    get_polytracker_tdag().open_file(fd, path);
  }

  *ret_label = 0;
  return fd;
}

static FILE *impl_fopen(const char *filename, const char *mode,
                        dfsan_label *ret_label) {
  FILE *fd = fopen(filename, mode);

  if (fd) {
    get_polytracker_tdag().open_file(fileno(fd), filename);
  }

  *ret_label = 0;
  return fd;
}

// Wrapper method for tainting a buffer, from source `fd` at `offset` having
// `length`. If length is invalid nothing happpens.
static void taint_source_buffer(int fd, void *buff, Offset offset,
                                Length length, dfsan_label &ret_label) {
  if (length.valid()) {
    get_polytracker_tdag().source_taint(fd, buff, offset, *length.value());
  }

  ret_label = 0;
}

// Implementation for the `getc`-style function (`getchar`, `getc`, `fgetc`,...)
// `ret_label` is the label for the return value. It will be assigned the source
// label (if any), unless EOF is reached. `file` is the file stream to read from
// `getchar_function` is the current function to implement
// `getchar_arg` is the optional arg to pass to the getchar_function.
template <typename F, typename... Args>
static int impl_getc_style_functions(dfsan_label &ret_label, FILE *file,
                                     F &&getchar_function,
                                     Args... getchar_arg) {
  static_assert(sizeof...(getchar_arg) <= 1,
                "Expected zero or one argument to the getchar_function");

  auto offset = Offset::from_file(file);
  int c = getchar_function(getchar_arg...);
  ret_label = 0;
  if (c != EOF) {
    if (auto tr = get_polytracker_tdag().source_taint(fileno(file), offset,
                                                      sizeof(char))) {
      ret_label = tr.value().first;
    }
  }
  return c;
}

// Implements taint source functions for read-style functions with known offset.
// `ret_label` is the label of the return value (will be set to zero)
// `offset` is the known offset the read starts from
// `retval` return value of read-like function
// `fd` the file descriptor reading from
// `buffer` the buffer that will be tainted
static ssize_t impl_offset_read_functions(dfsan_label &ret_label, Offset offset,
                                          ssize_t retval, int fd,
                                          void *buffer) {
  auto length = Length::from_returned_size(retval);
  taint_source_buffer(fd, buffer, offset, length, ret_label);
  return retval;
}

// Implements taint source functions for read/recv-style functions
// `ret_label` is the label of the return value (will be set to zero)
// `fd` the file descriptor reading from
// `buffer` the buffer that will be tainted
// `read_function` is the actual read function (e.g. `read` or `recv`)
// `read_function_args` are the arguments being passed to `read_function`
template <typename F, typename... Args>
static ssize_t impl_read_recv_functions(dfsan_label &ret_label, int fd,
                                        void *buffer, F &&read_function,
                                        Args... read_function_args) {
  auto offset = Offset::from_fd(fd);
  auto ret = read_function(read_function_args...);
  return impl_offset_read_functions(ret_label, offset, ret, fd, buffer);
}

// Implementation for the `fread`-style functions
// `ret_label` is the label for the return value. It will be assigned the source
// label (if any), unless EOF is reached. `file` is the file stream to read from
// `getchar_function` is the current function to implement
// `getchar_arg` is the optional arg to pass to the getchar_function.
template <typename F>
static size_t impl_fread(F &&fread_function, FILE *fd, void *buff, size_t size,
                         size_t count, dfsan_label &ret_label) {
  auto offset = Offset::from_file(fd);
  size_t ret = fread_function(buff, size, count, fd);
  auto length = Length::from_returned_size_count(size, ret);
  taint_source_buffer(fileno(fd), buff, offset, length, ret_label);
  return ret;
}

} // namespace

EXT_C_FUNC int __dfsw_open(const char *path, int oflags, dfsan_label path_label,
                           dfsan_label flag_label, dfsan_label *va_labels,
                           dfsan_label *ret_label, ...) {
  return impl_open(path, oflags, path_label, flag_label, va_labels, ret_label);
}

EXT_C_FUNC int __dfsw_open64(const char *path, int oflags,
                             dfsan_label path_label, dfsan_label flag_label,
                             dfsan_label *va_labels, dfsan_label *ret_label,
                             ...) {
  return impl_open(path, oflags, path_label, flag_label, va_labels, ret_label);
}

EXT_C_FUNC int __dfsw_openat(int dirfd, const char *path, int oflags,
                             dfsan_label path_label, dfsan_label flag_label,
                             dfsan_label *va_labels, dfsan_label *ret_label,
                             ...) {
  va_list args;
  va_start(args, ret_label);
  int fd = openat(dirfd, path, oflags, args);
  va_end(args);

  if (fd >= 0) {
    get_polytracker_tdag().open_file(fd, path);
  }

  *ret_label = 0;
  return fd;
}

EXT_C_FUNC FILE *__dfsw_fopen64(const char *filename, const char *mode,
                                dfsan_label fn_label, dfsan_label mode_label,
                                dfsan_label *ret_label) {
  return impl_fopen(filename, mode, ret_label);
}

EXT_C_FUNC FILE *__dfsw_fopen(const char *filename, const char *mode,
                              dfsan_label fn_label, dfsan_label mode_label,
                              dfsan_label *ret_label) {
  return impl_fopen(filename, mode, ret_label);
}

EXT_C_FUNC int __dfsw_close(int fd, dfsan_label fd_label,
                            dfsan_label *ret_label) {
  int ret = close(fd);

  if (ret == 0)
    get_polytracker_tdag().close_file(fd);

  *ret_label = 0;
  return ret;
}

EXT_C_FUNC int __dfsw_fclose(FILE *fd, dfsan_label fd_label,
                             dfsan_label *ret_label) {
  int fno = fileno(fd);
  int ret = fclose(fd);

  if (ret == 0)
    get_polytracker_tdag().close_file(fno);
  *ret_label = 0;
  return ret;
}

EXT_C_FUNC ssize_t __dfsw_read(int fd, void *buff, size_t size,
                               dfsan_label fd_label, dfsan_label buff_label,
                               dfsan_label size_label, dfsan_label *ret_label) {
  return impl_read_recv_functions(*ret_label, fd, buff, read, fd, buff, size);
}

EXT_C_FUNC ssize_t __dfsw_pread(int fd, void *buf, size_t count, off_t offset,
                                dfsan_label fd_label, dfsan_label buf_label,
                                dfsan_label count_label,
                                dfsan_label offset_label,
                                dfsan_label *ret_label) {
  return impl_offset_read_functions(*ret_label, Offset::from_off_t(offset),
                                    pread(fd, buf, count, offset), fd, buf);
}

EXT_C_FUNC ssize_t __dfsw_pread64(int fd, void *buf, size_t count, off_t offset,
                                  dfsan_label fd_label, dfsan_label buf_label,
                                  dfsan_label count_label,
                                  dfsan_label offset_label,
                                  dfsan_label *ret_label) {
  return impl_offset_read_functions(*ret_label, Offset::from_off_t(offset),
                                    pread(fd, buf, count, offset), fd, buf);
}

EXT_C_FUNC size_t __dfsw_fread(void *buff, size_t size, size_t count, FILE *fd,
                               dfsan_label buf_label, dfsan_label size_label,
                               dfsan_label count_label, dfsan_label fd_label,
                               dfsan_label *ret_label) {
  return impl_fread(fread, fd, buff, size, count, *ret_label);
}

EXT_C_FUNC size_t __dfsw_fread_unlocked(void *buff, size_t size, size_t count,
                                        FILE *fd, dfsan_label buf_label,
                                        dfsan_label size_label,
                                        dfsan_label count_label,
                                        dfsan_label fd_label,
                                        dfsan_label *ret_label) {
  return impl_fread(fread_unlocked, fd, buff, size, count, *ret_label);
}

EXT_C_FUNC int __dfsw_fgetc(FILE *fd, dfsan_label fd_label,
                            dfsan_label *ret_label) {
  return impl_getc_style_functions(*ret_label, fd, fgetc, fd);
}

EXT_C_FUNC int __dfsw_fgetc_unlocked(FILE *fd, dfsan_label fd_label,
                                     dfsan_label *ret_label) {
  return impl_getc_style_functions(*ret_label, fd, fgetc_unlocked, fd);
}

EXT_C_FUNC int __dfsw__IO_getc(FILE *fd, dfsan_label fd_label,
                               dfsan_label *ret_label) {
  return impl_getc_style_functions(*ret_label, fd, getc, fd);
}

EXT_C_FUNC int __dfsw_getc(FILE *fd, dfsan_label fd_label,
                           dfsan_label *ret_label) {
  return impl_getc_style_functions(*ret_label, fd, getc, fd);
}

EXT_C_FUNC int __dfsw_getc_unlocked(FILE *fd, dfsan_label fd_label,
                                    dfsan_label *ret_label) {
  return impl_getc_style_functions(*ret_label, fd, getc_unlocked, fd);
}

EXT_C_FUNC int __dfsw_getchar(dfsan_label *ret_label) {
  return impl_getc_style_functions(*ret_label, stdin, getchar);
}

EXT_C_FUNC int __dfsw_getchar_unlocked(dfsan_label *ret_label) {
  return impl_getc_style_functions(*ret_label, stdin, getchar_unlocked);
}

EXT_C_FUNC char *__dfsw_fgets(char *str, int count, FILE *fd,
                              dfsan_label str_label, dfsan_label count_label,
                              dfsan_label fd_label, dfsan_label *ret_label) {
  auto offset = Offset::from_file(fd);
  char *ret = fgets(str, count, fd);
  auto length = Length::from_returned_string(ret);
  taint_source_buffer(fileno(fd), str, offset, length, *ret_label);
  if (length.valid()) {
    *ret_label = str_label;
  }
  return ret;
}

// TODO (hbrodin): Should this be removed? The call to fgets doesn't seem right,
// especially then length is sizeof char*, typically eight. In general it is
// unbounded and the gets-function is deprecated.
EXT_C_FUNC char *__dfsw_gets(char *str, dfsan_label str_label,
                             dfsan_label *ret_label) {
  auto offset = Offset::from_file(stdin);
  char *ret = fgets(str, sizeof str, stdin);

  if (ret) {
    size_t len = strlen(ret);
    get_polytracker_tdag().source_taint(fileno(stdin), str, offset, len);
    *ret_label = str_label;
  } else {
    *ret_label = 0;
  }

  return ret;
}

EXT_C_FUNC ssize_t __dfsw_getdelim(char **lineptr, size_t *n, int delim,
                                   FILE *fd, dfsan_label buf_label,
                                   dfsan_label size_label,
                                   dfsan_label delim_label,
                                   dfsan_label fd_label,
                                   dfsan_label *ret_label) {
  auto offset = Offset::from_file(fd);
  auto ret = getdelim(lineptr, n, delim, fd);
  auto length = Length::from_returned_size(ret);
  taint_source_buffer(fileno(fd), *lineptr, offset, length, *ret_label);
  return ret;
}

EXT_C_FUNC ssize_t __dfsw___getdelim(char **lineptr, size_t *n, int delim,
                                     FILE *fd, dfsan_label buf_label,
                                     dfsan_label size_label,
                                     dfsan_label delim_label,
                                     dfsan_label fd_label,
                                     dfsan_label *ret_label) {
  auto offset = Offset::from_file(fd);
  auto ret = __getdelim(lineptr, n, delim, fd);
  auto length = Length::from_returned_size(ret);
  taint_source_buffer(fileno(fd), *lineptr, offset, length, *ret_label);
  return ret;
}

EXT_C_FUNC void *__dfsw_mmap(void *start, size_t length, int prot, int flags,
                             int fd, off_t offset, dfsan_label start_label,
                             dfsan_label len_label, dfsan_label prot_label,
                             dfsan_label flags_label, dfsan_label fd_label,
                             dfsan_label offset_label, dfsan_label *ret_label) {
  auto offs = Offset::from_off_t(offset);
  void *ret = mmap(start, length, prot, flags, fd, offset);
  if (ret != MAP_FAILED) {
    get_polytracker_tdag().source_taint(fd, ret, offs, length);
  }

  *ret_label = 0;
  return ret;
}

EXT_C_FUNC int __dfsw_munmap(void *addr, size_t length, dfsan_label addr_label,
                             dfsan_label length_label, dfsan_label *ret_label) {
#ifdef DEBUG_INFO
  fprintf(stderr, "### munmap, addr %p, length %zu \n", addr, length);
#endif
  int ret = munmap(addr, length);
  dfsan_set_label(0, addr, length);
  *ret_label = 0;
  return ret;
}

EXT_C_FUNC int __dfsw__putc(int __c, FILE *__fp, dfsan_label c_label,
                            dfsan_label fp_label, dfsan_label *ret_label) {
  *ret_label = 0;
  return putc(__c, __fp);
}

EXT_C_FUNC int __dfsw_pthread_cond_broadcast(pthread_cond_t *cond,
                                             dfsan_label cond_label,
                                             dfsan_label *ret_label) {
  *ret_label = 0;
  return pthread_cond_broadcast(cond);
}

EXT_C_FUNC void __dfsw_exit(int ret_code, dfsan_label ret_code_label) {
  exit(ret_code);
}

// Need this for some reason. Not sure why. Should already be in assert.h.
extern "C" void __assert_fail(const char *, const char *, unsigned,
                              const char *);
// Capture calls to abort and explicitly invoke polytracker_end to do a best
// effort at updating the tdag with correct sizes.
EXT_C_FUNC void __dfsw___assert_fail(const char *msg, const char *file,
                                     unsigned line, const char *pretty_func,
                                     dfsan_label msg_label,
                                     dfsan_label file_label,
                                     dfsan_label line_label,
                                     dfsan_label pretty_func_label) {
  polytracker_end();
  __assert_fail(msg, file, line, pretty_func);
}

// Socket functions
namespace {
static std::optional<std::string> connect_name(int socket) {
  sockaddr_in local_addr, remote_addr;
  socklen_t local_len{sizeof(local_addr)}, remote_len{sizeof(remote_addr)};
  char local_str[64], remote_str[64];

  if (int ret = getsockname(socket, reinterpret_cast<sockaddr *>(&local_addr),
                            &local_len);
      ret != 0) {
    taintdag::error_exit("Failed to get sockname for socket ", socket);
  }

  // The only supported address family for now is AF_INET
  if (local_addr.sin_family != AF_INET)
    return {};

  if (int ret = getpeername(socket, reinterpret_cast<sockaddr *>(&remote_addr),
                            &remote_len);
      ret != 0) {
    taintdag::error_exit("Failed to get peername for socket ", socket);
  }

  if (!inet_ntop(AF_INET, &(local_addr.sin_addr), local_str,
                 sizeof(local_str))) {
    taintdag::error_exit("inet_ntop failed for remote addr");
  }

  if (!inet_ntop(AF_INET, &(remote_addr.sin_addr), remote_str,
                 sizeof(remote_str))) {
    taintdag::error_exit("inet_ntop failed for remote addr");
  }

  std::stringstream strm;
  strm << "socket:" << local_str << ":" << ntohs(local_addr.sin_port) << "-"
       << remote_str << ":" << ntohs(remote_addr.sin_port);

  return strm.str();
}
} // namespace

EXT_C_FUNC int __dfsw_accept(int socket, struct sockaddr *address,
                             socklen_t *address_len, dfsan_label socket_label,
                             dfsan_label address_label,
                             dfsan_label address_len_label,
                             dfsan_label *ret_label) {
  int client_socket = accept(socket, address, address_len);
  if (client_socket >= 0) {
    if (auto name = connect_name(client_socket); name) {
      get_polytracker_tdag().open_file(client_socket, *name);
    }
  }

  *ret_label = 0;
  return client_socket;
}

EXT_C_FUNC int __dfsw_accept4(int socket, struct sockaddr *address,
                             socklen_t *address_len, int flags, 
                             dfsan_label socket_label,
                             dfsan_label address_label,
                             dfsan_label address_len_label,
                             dfsan_label *ret_label) {
  int client_socket = accept4(socket, address, address_len, flags);
  if (client_socket >= 0) {
    if (auto name = connect_name(client_socket); name) {
      get_polytracker_tdag().open_file(client_socket, *name);
    }
  }

  *ret_label = 0;
  return client_socket;
}

EXT_C_FUNC int __dfsw_connect(int socket, const struct sockaddr *address,
                              socklen_t address_len, dfsan_label socket_label,
                              dfsan_label address_label,
                              dfsan_label address_len_label,
                              dfsan_label *ret_label) {
  int status = connect(socket, address, address_len);
  if (status == 0) {
    if (auto name = connect_name(socket); name) {
      get_polytracker_tdag().open_file(socket, *name);
    }
  }

  *ret_label = 0;
  return status;
}

EXT_C_FUNC ssize_t __dfsw_recv(int socket, void *buff, size_t length, int flags,
                               dfsan_label socket_label, dfsan_label buff_label,
                               dfsan_label length_label,
                               dfsan_label flags_label,
                               dfsan_label *ret_label) {
  return impl_read_recv_functions(*ret_label, socket, buff, recv, socket, buff,
                                  length, flags);
}

EXT_C_FUNC ssize_t __dfsw_recvfrom(
    int socket, void *buffer, size_t length, int flags,
    struct sockaddr *address, socklen_t *address_len, dfsan_label socket_label,
    dfsan_label buffer_label, dfsan_label length_label, dfsan_label flags_label,
    dfsan_label address_label, dfsan_label address_len_label,
    dfsan_label *ret_label) {
  return impl_read_recv_functions(*ret_label, socket, buffer, recvfrom, socket,
                                  buffer, length, flags, address, address_len);
}