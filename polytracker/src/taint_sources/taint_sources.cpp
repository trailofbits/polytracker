#include "polytracker/taint_sources.h"
#include "polytracker/early_construct.h"
#include "polytracker/polytracker.h"

#include "taintdag/error.h"
#include "taintdag/polytracker.h"

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

static ssize_t impl_pread(int fd, void *buf, size_t count, off_t offset,
                          dfsan_label *ret_label) {
  ssize_t ret = pread(fd, buf, count, offset);
  if (ret > 0)
    get_polytracker_tdag().source_taint(fd, buf, offset, ret);
  *ret_label = 0;
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
  long read_start = lseek(fd, 0, SEEK_CUR);
  ssize_t ret_val = read(fd, buff, size);

  if (ret_val > 0)
    get_polytracker_tdag().source_taint(fd, buff, read_start, ret_val);

  *ret_label = 0;
  return ret_val;
}

EXT_C_FUNC ssize_t __dfsw_pread(int fd, void *buf, size_t count, off_t offset,
                                dfsan_label fd_label, dfsan_label buf_label,
                                dfsan_label count_label,
                                dfsan_label offset_label,
                                dfsan_label *ret_label) {
  return impl_pread(fd, buf, count, offset, ret_label);
}

EXT_C_FUNC ssize_t __dfsw_pread64(int fd, void *buf, size_t count, off_t offset,
                                  dfsan_label fd_label, dfsan_label buf_label,
                                  dfsan_label count_label,
                                  dfsan_label offset_label,
                                  dfsan_label *ret_label) {
  return impl_pread(fd, buf, count, offset, ret_label);
}

EXT_C_FUNC size_t __dfsw_fread(void *buff, size_t size, size_t count, FILE *fd,
                               dfsan_label buf_label, dfsan_label size_label,
                               dfsan_label count_label, dfsan_label fd_label,
                               dfsan_label *ret_label) {
  long offset = ftell(fd);
  size_t ret = fread(buff, size, count, fd);

  if (ret > 0)
    get_polytracker_tdag().source_taint(fileno(fd), buff, offset, ret * size);
  *ret_label = 0;
  return ret;
}

EXT_C_FUNC size_t __dfsw_fread_unlocked(void *buff, size_t size, size_t count,
                                        FILE *fd, dfsan_label buf_label,
                                        dfsan_label size_label,
                                        dfsan_label count_label,
                                        dfsan_label fd_label,
                                        dfsan_label *ret_label) {
  long offset = ftell(fd);
  size_t ret = fread_unlocked(buff, size, count, fd);
  if (ret > 0)
    get_polytracker_tdag().source_taint(fileno(fd), buff, offset, ret * size);
  *ret_label = 0;
  return ret;
}
EXT_C_FUNC int __dfsw_fgetc(FILE *fd, dfsan_label fd_label,
                            dfsan_label *ret_label) {
  long offset = ftell(fd);
  int c = fgetc(fd);
  *ret_label = 0;

  if (c != EOF) {
    auto tr =
        get_polytracker_tdag().source_taint(fileno(fd), offset, sizeof(char));
    if (tr)
      *ret_label = tr.value().first;
  }
  return c;
}

EXT_C_FUNC int __dfsw_fgetc_unlocked(FILE *fd, dfsan_label fd_label,
                                     dfsan_label *ret_label) {
  long offset = ftell(fd);
  int c = fgetc_unlocked(fd);
  *ret_label = 0;
  if (c != EOF) {
    auto tr =
        get_polytracker_tdag().source_taint(fileno(fd), offset, sizeof(char));
    if (tr)
      *ret_label = tr.value().first;
  }
  return c;
}

EXT_C_FUNC int __dfsw__IO_getc(FILE *fd, dfsan_label fd_label,
                               dfsan_label *ret_label) {
  long offset = ftell(fd);
  int c = getc(fd);
  *ret_label = 0;
  if (c != EOF) {
    auto tr =
        get_polytracker_tdag().source_taint(fileno(fd), offset, sizeof(char));
    if (tr)
      *ret_label = tr.value().first;
  }
  return c;
}

EXT_C_FUNC int __dfsw_getc(FILE *fd, dfsan_label fd_label,
                           dfsan_label *ret_label) {
  long offset = ftell(fd);
  int c = getc(fd);
  *ret_label = 0;
  if (c != EOF) {
    auto tr =
        get_polytracker_tdag().source_taint(fileno(fd), offset, sizeof(char));
    if (tr)
      *ret_label = tr.value().first;
  }
  return c;
}

EXT_C_FUNC int __dfsw_getc_unlocked(FILE *fd, dfsan_label fd_label,
                                    dfsan_label *ret_label) {
  long offset = ftell(fd);
  int c = getc_unlocked(fd);
  *ret_label = 0;
  if (c != EOF) {
    auto tr =
        get_polytracker_tdag().source_taint(fileno(fd), offset, sizeof(char));
    if (tr)
      *ret_label = tr.value().first;
  }
  return c;
}

EXT_C_FUNC int __dfsw_getchar(dfsan_label *ret_label) {
  long offset = ftell(stdin);
  int c = getchar();
  *ret_label = 0;
  if (c != EOF) {
    auto tr = get_polytracker_tdag().source_taint(fileno(stdin), offset,
                                                  sizeof(char));
    if (tr)
      *ret_label = tr.value().first;
  }
  return c;
}

EXT_C_FUNC int __dfsw_getchar_unlocked(dfsan_label *ret_label) {
  long offset = ftell(stdin);
  int c = getchar_unlocked();
  *ret_label = 0;
  if (c != EOF) {
    auto tr = get_polytracker_tdag().source_taint(fileno(stdin), offset,
                                                  sizeof(char));
    if (tr)
      *ret_label = tr.value().first;
  }
  return c;
}

EXT_C_FUNC char *__dfsw_fgets(char *str, int count, FILE *fd,
                              dfsan_label str_label, dfsan_label count_label,
                              dfsan_label fd_label, dfsan_label *ret_label) {
  long offset = ftell(fd);
  char *ret = fgets(str, count, fd);

  if (ret) {
    size_t len = strlen(ret);
    get_polytracker_tdag().source_taint(fileno(fd), str, offset, len);
    *ret_label = str_label;
  } else {
    *ret_label = 0;
  }
  return ret;
}

EXT_C_FUNC char *__dfsw_gets(char *str, dfsan_label str_label,
                             dfsan_label *ret_label) {
  long offset = ftell(stdin);
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
  long offset = ftell(fd);
  ssize_t ret = getdelim(lineptr, n, delim, fd);

  if (ret != -1) {
    get_polytracker_tdag().source_taint(fileno(fd), *lineptr, offset, ret);
  }

  *ret_label = 0;
  return ret;
}

EXT_C_FUNC ssize_t __dfsw___getdelim(char **lineptr, size_t *n, int delim,
                                     FILE *fd, dfsan_label buf_label,
                                     dfsan_label size_label,
                                     dfsan_label delim_label,
                                     dfsan_label fd_label,
                                     dfsan_label *ret_label) {
  long offset = ftell(fd);
  ssize_t ret = __getdelim(lineptr, n, delim, fd);

  if (ret != -1) {
    get_polytracker_tdag().source_taint(fileno(fd), *lineptr, offset, ret);
  }

  *ret_label = 0;
  return ret;
}

EXT_C_FUNC void *__dfsw_mmap(void *start, size_t length, int prot, int flags,
                             int fd, off_t offset, dfsan_label start_label,
                             dfsan_label len_label, dfsan_label prot_label,
                             dfsan_label flags_label, dfsan_label fd_label,
                             dfsan_label offset_label, dfsan_label *ret_label) {
  void *ret = mmap(start, length, prot, flags, fd, offset);
  if (ret != MAP_FAILED) {
    get_polytracker_tdag().source_taint(fd, ret, offset, length);
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

// Socket functions

// TODO (hbrodin): Should this be moved somewhere in the PolyTracker class?
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

EXT_C_FUNC int __dfsw_accept(int socket, struct sockaddr *address,
                             socklen_t *address_len, dfsan_label socket_label,
                             dfsan_label address_label,
                             dfsan_label address_len_label,
                             dfsan_label *ret_label) {
  int client_socket = ::accept(socket, address, address_len);
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
  int status = ::connect(socket, address, address_len);
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
  ssize_t ret_val = recv(socket, buff, length, flags);

  if (ret_val > 0)
    get_polytracker_tdag().source_taint(socket, buff, -1, ret_val);

  *ret_label = 0;
  return ret_val;
}

EXT_C_FUNC ssize_t __dfsw_recvfrom(
    int socket, void *buffer, size_t length, int flags,
    struct sockaddr *address, socklen_t *address_len, dfsan_label socket_label,
    dfsan_label buffer_label, dfsan_label length_label, dfsan_label flags_label,
    dfsan_label address_label, dfsan_label address_len_label,
    dfsan_label *ret_label) {
  ssize_t ret_val =
      recvfrom(socket, buffer, length, flags, address, address_len);

  if (ret_val > 0)
    get_polytracker_tdag().source_taint(socket, buffer, -1, ret_val);

  *ret_label = 0;
  return ret_val;
}