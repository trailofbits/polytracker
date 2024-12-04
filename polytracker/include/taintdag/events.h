
/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "taintdag/fnmapping.h"

namespace taintdag {

namespace detail {
// A uint32_t varint encoded by setting highest bit for all but the final byte.
// Requires up to 5 bytes of storage as each output byte uses 7 input bits.
// Total maximum need is floor(32/7) = 5. Returns number of bytes required.
size_t varint_encode(uint32_t val, uint8_t *buffer) {
  auto orig_buffer = buffer;
  while (val >= 0x80) {
    *buffer++ = 0x80 | (val & 0x7f);
    val >>= 7;
  }
  *buffer++ = val & 0x7f;
  return buffer - orig_buffer;
}
// TODO (hbrodin): Should probably used std::span
} // namespace detail

struct Events : public SectionBase {
  enum kind_t : uint8_t { entry, exit, taint };

  static constexpr uint8_t tag{8};
  static constexpr size_t align_of{1};
  static constexpr size_t allocation_size{1024 * 1024 * 1024};

  template <typename OF> Events(SectionArg<OF> of) : SectionBase(of.range) {}

  void log_fn_event(kind_t kind, Functions::index_t idx);
  void log_cf_event(label_t label, Functions::index_t idx);
};

} // namespace taintdag
