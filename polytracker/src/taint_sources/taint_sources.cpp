//#include "dfsan/dfsan.h"
#include "polytracker/taint_sources.h"
#include "polytracker/early_construct.h"
#include "polytracker/logging.h"
#include "polytracker/output.h"
#include "polytracker/polytracker.h"
#include "polytracker/taint.h"

#include "taintdag/polytracker.h"

#include <algorithm>
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

extern sqlite3 *output_db;
EARLY_CONSTRUCT_EXTERN_GETTER(fd_input_map_t, fd_input_map);

EARLY_CONSTRUCT_EXTERN_GETTER(taintdag::PolyTracker, polytracker_tdag);

// To create some label functions
// Following the libc custom functions from custom.cc
EXT_C_FUNC int __dfsw_open(const char *path, int oflags, dfsan_label path_label,
                           dfsan_label flag_label, dfsan_label *va_labels,
                           dfsan_label *ret_label, ...) {
  va_list args;
  va_start(args, ret_label);
  int fd = open(path, oflags, args);
  va_end(args);
#ifdef DEBUG_INFO
  fprintf(stderr, "open: filename is : %s, fd is %d \n", path, fd);
#endif
  if (fd >= 0 && isTrackingSource(path)) {
#ifdef DEBUG_INFO
    std::cout << "open: adding new taint info!" << std::endl;
#endif
    // This should be passed by reference all the way down
    // This should only be called a few times, typically once to create the
    // taint source So creating an object here is low-ish overhead.
    std::string track_path{path};
    addDerivedSource(track_path, fd);
  } else if (fd >= 0 && ((oflags & O_WRONLY) || (oflags & O_RDWR))) {
    // We're not tracking this source, but its writeable
    // create a new input, range is 0->0 as we arent tracking anything for now.
    // just need this input id in the database, todo, could be output id
    auto input_id = storeNewInput(output_db, path, 0, 0, 0);
    get_fd_input_map()[fd] = input_id;
  }

  if (fd >=0) {
    get_polytracker_tdag().open_file(fd, path);
  }

  *ret_label = 0;
  return fd;
}

EXT_C_FUNC int __dfsw_openat(int dirfd, const char *path, int oflags,
                             dfsan_label path_label, dfsan_label flag_label,
                             dfsan_label *va_labels, dfsan_label *ret_label,
                             ...) {
  va_list args;
  va_start(args, ret_label);
  int fd = openat(dirfd, path, oflags, args);
  va_end(args);
#ifdef DEBUG_INFO
  fprintf(stderr, "openat: filename is : %s, fd is %d \n", path, fd);
#endif
  if (fd >= 0 && isTrackingSource(path)) {
#ifdef DEBUG_INFO
    std::cout << "openat: adding new taint info!" << std::endl;
#endif
    std::string track_path{path};
    addDerivedSource(track_path, fd);
  } else if (fd >= 0 && ((oflags & O_WRONLY) || (oflags & O_RDWR))) {
    // We're not tracking this source, but its writeable
    // create a new input, range is 0->0 as we arent tracking anything for now.
    // just need this input id in the database, todo, could be output id
    auto input_id = storeNewInput(output_db, path, 0, 0, 0);
    get_fd_input_map()[fd] = input_id;
  }

  if (fd >=0) {
    get_polytracker_tdag().open_file(fd, path);
  }

  *ret_label = 0;
  return fd;
}

EXT_C_FUNC FILE *__dfsw_fopen64(const char *filename, const char *mode,
                                dfsan_label fn_label, dfsan_label mode_label,
                                dfsan_label *ret_label) {
  FILE *fd = fopen(filename, mode);
#ifdef DEBUG_INFO
  fprintf(stderr, "### fopen64, filename is : %s, fd is %p \n", filename, fd);
  fflush(stderr);
#endif
  if (fd != NULL && isTrackingSource(filename)) {
#ifdef DEBUG_INFO
    std::cout << "fopen64: adding new taint info!" << std::endl;
#endif
    std::string track_path{filename};
    addDerivedSource(track_path, fileno(fd));
  } else {
    auto fid = fileno(fd);
    auto oflags = fcntl(fid, F_GETFL);
    if ((oflags & O_WRONLY) || (oflags & O_RDWR)) {
      // the file is writable
      auto input_id = storeNewInput(output_db, filename, 0, 0, 0);
      get_fd_input_map()[fid] = input_id;
    }
  }

  if (fd) {
    get_polytracker_tdag().open_file(fileno(fd), filename);
  }

  *ret_label = 0;
  return fd;
}

EXT_C_FUNC FILE *__dfsw_fopen(const char *filename, const char *mode,
                              dfsan_label fn_label, dfsan_label mode_label,
                              dfsan_label *ret_label) {
  FILE *fd = fopen(filename, mode);
#ifdef DEBUG_INFO
  fprintf(stderr, "### fopen, filename is : %s, fd is %p \n", filename, fd);
#endif
  if (fd != NULL && isTrackingSource(filename)) {
#ifdef DEBUG_INFO
    std::cout << "fopen: adding new taint info!" << std::endl;
#endif
    std::string track_path{filename};
    addDerivedSource(track_path, fileno(fd));
  } else {
    auto fid = fileno(fd);
    auto oflags = fcntl(fid, F_GETFL);
    if ((oflags & O_WRONLY) || (oflags & O_RDWR)) {
      // the file is writable
      auto input_id = storeNewInput(output_db, filename, 0, 0, 0);
      get_fd_input_map()[fid] = input_id;
    }
  }

  if (fd) {
    get_polytracker_tdag().open_file(fileno(fd), filename);
  }

  *ret_label = 0;
  return fd;
}

EXT_C_FUNC int __dfsw_close(int fd, dfsan_label fd_label,
                            dfsan_label *ret_label) {
  int ret = close(fd);
#ifdef DEBUG_INFO
  fprintf(stderr, "### close, fd is %d , ret is %d \n", fd, ret);
#endif
  if (ret == 0 && isTrackingSource(fd)) {
    closeSource(fd);
  }
  
  if (ret == 0)
    get_polytracker_tdag().close_file(fd);

  *ret_label = 0;
  return ret;
}

EXT_C_FUNC int __dfsw_fclose(FILE *fd, dfsan_label fd_label,
                             dfsan_label *ret_label) {
  int fno = fileno(fd);
  int ret = fclose(fd);
#ifdef DEBUG_INFO
  fprintf(stderr, "### close, fd is %p, ret is %d \n", fd, ret);
#endif
  if (ret == 0 && isTrackingSource(fno)) {
    closeSource(fno);
  }

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

#ifdef DEBUG_INFO
  fprintf(stderr, "read: fd is %d, buffer addr is %p, size is %ld\n", fd, buff,
          size);
#endif
  // Check if we are tracking this fd.
  if (isTrackingSource(fd)) {
    if (ret_val > 0) {
      bool res = taintData(fd, (char *)buff, read_start, ret_val);
      if (res == false) {
        std::cerr << "### read: error, data not tainted" << std::endl;
      }
    }
    *ret_label = 0;
  } else {
    *ret_label = 0;
  }


  if (ret_val > 0)
    get_polytracker_tdag().source_taint(fd, buff, read_start, ret_val);

  return ret_val;
}

EXT_C_FUNC ssize_t __dfsw_pread(int fd, void *buf, size_t count, off_t offset,
                                dfsan_label fd_label, dfsan_label buf_label,
                                dfsan_label count_label,
                                dfsan_label offset_label,
                                dfsan_label *ret_label) {
  ssize_t ret = pread(fd, buf, count, offset);
  if (isTrackingSource(fd)) {
    if (ret > 0) {
      bool res = taintData(fd, (char *)buf, offset, ret);
      if (res == false) {
        std::cerr << "### pread: error, data not tainted" << std::endl;
      }
    }
    *ret_label = 0;
  } else {
    *ret_label = 0;
  }
  if (ret> 0)
    get_polytracker_tdag().source_taint(fd, buf, offset, ret);
  return ret;
}

EXT_C_FUNC ssize_t __dfsw_pread64(int fd, void *buf, size_t count, off_t offset,
                                  dfsan_label fd_label, dfsan_label buf_label,
                                  dfsan_label count_label,
                                  dfsan_label offset_label,
                                  dfsan_label *ret_label) {
#ifdef DEBUG_INFO
  std::cout << "Inside of pread64" << std::endl;
#endif
  ssize_t ret = pread(fd, buf, count, offset);
  if (isTrackingSource(fd)) {
    if (ret > 0) {
      bool res = taintData(fd, (char *)buf, offset, ret);
      if (res == false) {
        std::cerr << "### pread64: error, data not tainted" << std::endl;
      }
    }
    *ret_label = 0;
  } else {
    *ret_label = 0;
  }
  if (ret> 0)
    get_polytracker_tdag().source_taint(fd, buf, offset, ret);
  return ret;
}

EXT_C_FUNC size_t __dfsw_fread(void *buff, size_t size, size_t count, FILE *fd,
                               dfsan_label buf_label, dfsan_label size_label,
                               dfsan_label count_label, dfsan_label fd_label,
                               dfsan_label *ret_label) {
  long offset = ftell(fd);
  size_t ret = fread(buff, size, count, fd);
#ifdef DEBUG_INFO
  fprintf(stderr, "### fread, fd is %p \n", fd);
  fflush(stderr);
#endif
  if (isTrackingSource(fileno(fd))) {
    if (ret > 0) {
      // fread returns number of objects read specified by size
      bool res = taintData(fileno(fd), (char *)buff, offset, ret * size);
      if (res == false) {
        std::cerr << "### fread: error, data not tainted" << std::endl;
      }
    }
    *ret_label = 0;
  } else {
#ifdef DEBUG_INFO
    fprintf(stderr, "### fread, not target fd!\n");
    fflush(stderr);
#endif
    *ret_label = 0;
  }

  if (ret> 0)
    get_polytracker_tdag().source_taint(fileno(fd), buff, offset, ret);
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
#ifdef DEBUG_INFO
  fprintf(stderr, "### fread_unlocked %p,range is %ld, %ld/%ld\n", fd, offset,
          ret, count);
#endif
  if (isTrackingSource(fileno(fd))) {
    if (ret > 0) {
      bool res = taintData(fileno(fd), (char *)buff, offset, ret * size);
      if (res == false) {
        std::cerr << "### fread_unlocked: error, data not tainted" << std::endl;
      }
    }
    *ret_label = 0;
  } else {
    *ret_label = 0;
  }
  if (ret> 0)
    get_polytracker_tdag().source_taint(fileno(fd), buff, offset, ret);
  return ret;
}
EXT_C_FUNC int __dfsw_fgetc(FILE *fd, dfsan_label fd_label,
                            dfsan_label *ret_label) {
  long offset = ftell(fd);
  int c = fgetc(fd);
  *ret_label = 0;
#ifdef DEBUG_INFO
  fprintf(stderr, "### fgetc %p, range is %ld, 1 \n", fd, offset);
#endif
  if (c != EOF && isTrackingSource(fileno(fd))) {
    *ret_label = createReturnLabel(offset, getSourceName(fileno(fd)));
  }

  if (c != EOF) {
    auto tr = get_polytracker_tdag().source_taint(fileno(fd), offset, sizeof(char));
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
#ifdef DEBUG_INFO
  fprintf(stderr, "### fgetc_unlocked %p, range is %ld, 1 \n", fd, offset);
#endif
  if (c != EOF && isTrackingSource(fileno(fd))) {
    *ret_label = createReturnLabel(offset, getSourceName(fileno(fd)));
  }
  if (c != EOF) {
    auto tr = get_polytracker_tdag().source_taint(fileno(fd), offset, sizeof(char));
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
#ifdef DEBUG_INFO
  fprintf(stderr, "### _IO_getc %p, range is %ld, 1 , c is %d\n", fd, offset,
          c);
#endif
  if (isTrackingSource(fileno(fd)) && c != EOF) {
    *ret_label = createReturnLabel(offset, getSourceName(fileno(fd)));
  }
  if (c != EOF) {
    auto tr = get_polytracker_tdag().source_taint(fileno(fd), offset, sizeof(char));
    if (tr)
      *ret_label = tr.value().first;
  }
  return c;
}

EXT_C_FUNC int __dfsw_getchar(dfsan_label *ret_label) {
  long offset = ftell(stdin);
  int c = getchar();
  *ret_label = 0;
#ifdef DEBUG_INFO
  fprintf(stderr, "### getchar stdin, range is %ld, 1 \n", offset);
#endif
  if (c != EOF) {
    *ret_label = createReturnLabel(offset, getSourceName(fileno(stdin)));
  }
  if (c != EOF) {
    auto tr = get_polytracker_tdag().source_taint(fileno(stdin), offset, sizeof(char));
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
#ifdef DEBUG_INFO
  if (ret == nullptr) {
    fprintf(stderr, "fgets %p, range is %ld, %dd \n", fd, offset, 0);

  } else {
    fprintf(stderr, "fgets %p, range is %ld, %ld \n", fd, offset, strlen(ret));
  }
#endif
  if (ret && isTrackingSource(fileno(fd))) {
    int len = strlen(ret);
    bool res = taintData(fileno(fd), str, offset, len);
    if (res == false) {
      std::cerr << "### fgets: error, data not tainted" << std::endl;
    }
    *ret_label = str_label;
  } else {
    *ret_label = 0;
  }

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
#ifdef DEBUG_INFO
  fprintf(stderr, "gets stdin, range is %ld, %ld \n", offset, strlen(ret) + 1);
#endif
  if (ret) {
    bool res = taintData(fileno(stdin), str, offset, strlen(ret));
    if (res == false) {
      std::cerr << "### gets: error, data not tainted" << std::endl;
    }
    *ret_label = str_label;
  } else {
    *ret_label = 0;
  }

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
#ifdef DEBUG_INFO
  fprintf(stderr, "### getdelim %p,range is %ld, %ld\n", fd, offset, ret);
#endif
  if (ret > 0 && isTrackingSource(fileno(fd))) {
    bool res = taintData(fileno(fd), *lineptr, offset, ret);
    if (res == false) {
      std::cerr << "### getdelim: error, data not tainted" << std::endl;
    }
  }

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
#ifdef DEBUG_INFO
  fprintf(stderr, "### __getdelim %p,range is %ld, %ld\n", fd, offset, ret);
#endif
  if (ret > 0 && isTrackingSource(fileno(fd))) {
    bool res = taintData(fileno(fd), *lineptr, offset, ret);
    if (res == false) {
      std::cerr << "### __getdelim: error, data not tainted" << std::endl;
    }
  }
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
  if (ret && isTrackingSource(fd)) {
    bool res = taintData(fd, (char *)ret, offset, length);
    if (res == false) {
      std::cerr << "### mmap: error, data not tainted" << std::endl;
    }
  }

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
  polytracker_end();
  exit(ret_code);
}