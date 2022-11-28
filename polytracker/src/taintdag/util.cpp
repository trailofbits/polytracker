/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <stdio.h>
#include <unistd.h>

#include "taintdag/error.h"
#include "taintdag/util.h"

using namespace taintdag;

namespace util {

Length Length::from_returned_size(ssize_t retval) {
  if (retval > 0) {
    // All positive ssize_t can be represented in size_t
    return Length{static_cast<size_t>(retval)};
  }
  return Length{};
}

Length Length::from_returned_size_count(size_t size, size_t nitems) {

  size_t byte_size{0};

  // NOTE: using clang builtin. Assuming portability is not an issue as we rely
  // heavily on LLVM.
  static_assert(sizeof(size_t) == sizeof(unsigned long),
                "Implementation requires size_t is same size as unsigned long");
  if (__builtin_umull_overflow(size, nitems, &byte_size)) {
    error_exit("Length size ", size, " nitems ", nitems, " overflows");
  }

  // Nothing read
  if (byte_size == 0) {
    return Length{};
  }

  // Read ok
  return Length{byte_size};
}

Length Length::from_returned_string(char const *str) {
  if (str) {
    return Length{std::string_view{str}.length()};
  } else {
    return Length{};
  }
}

Length::Length(size_t length) : value_{length} {}

std::optional<size_t> const &Length::value() const { return value_; }

bool Length::valid() const { return value_.has_value(); }

Offset Offset::from_fd(int fd) {
  return Offset::from_off_t(lseek(fd, 0, SEEK_CUR));
}

Offset Offset::from_file(FILE *file) {
  return Offset::from_off_t(ftello(file));
}

Offset Offset::from_off_t(off_t offset_value) {
  if (offset_value < 0) {
    return Offset{};
  } else if (offset_value > max_source_offset) {
    // If this path is reached an offset that is larger than can be recorded
    // in the TDAG structure is encounteed. There is not much to do but bail
    // out.
    error_exit("Offset ", offset_value,
               " is larger than maximum offset that can be handled:",
               max_source_offset);
  }
  return Offset(offset_value);
}

Offset::Offset(off_t value) : value_(value) {}

std::optional<taintdag::source_offset_t> const &Offset::value() const {
  return value_;
}

bool Offset::valid() const { return value_.has_value(); }

} // namespace util
