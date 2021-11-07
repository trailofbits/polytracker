#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "gigafunction/gfrt/tracelib.h"

extern "C" char *gigafunction__getenv(char const *name) {
  auto ret = getenv(name);
  if (ret) {
    gigafunction::env(name, ret);
  }
  return ret;
}

extern "C" int gigafunction__open(const char *path, int oflag, ...) {
  int ret;
  va_list args;
  va_start(args, oflag);
  if (oflag & O_CREAT) {
    ret = ::open(path, oflag, va_arg(args, int));
  } else {
    ret = ::open(path, oflag);
  }

  gigafunction::openfd(ret, path);

  return ret;
}

extern "C" ssize_t gigafunction__read(int fildes, void *buf, size_t nbyte) {
  auto pos = ::lseek(fildes, 0, SEEK_CUR);
  auto ret = ::read(fildes, buf, nbyte);
  if (ret > 0)
    gigafunction::readfd(fildes, pos, ret);
  return ret;
}

extern "C" int gigafunction__close(int fildes) {
  auto ret = ::close(fildes);
  if (ret != -1)
    gigafunction::closefd(fildes);
  return ret;
}