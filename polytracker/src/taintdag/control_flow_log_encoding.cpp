/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/control_flow_log_encoding.h"

// Separate from control_flow_log.h to avoid duplicate symbol inclusion in
// testing
namespace taintdag {
// A uint32_t varint encoded by setting highest bit for all but the final byte.
// Requires up to 5 bytes of storage as each output byte uses 7 input bits.
// Total maximum need is floor(32/7) = 5.
size_t varint_encode(uint32_t val, uint8_t *buffer) {
  auto orig_buffer = buffer;
  while (val >= 0x80) {
    *buffer++ = 0x80 | (val & 0x7f);
    val >>= 7;
  }
  *buffer++ = val & 0x7f;
  return buffer - orig_buffer;
}
} // namespace taintdag