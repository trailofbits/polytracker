
/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "taintdag/outputfile.h"
#include "taintdag/section.h"
#include "taintdag/taint.h"
#include "taintdag/util.h"

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

struct ControlFlowLog : public SectionBase {
  enum EventType {
    EnterFunction = 0,
    LeaveFunction = 1,
    TaintedControlFlow = 2,
  };

  static constexpr uint8_t tag{8};
  static constexpr size_t align_of{1};
  static constexpr size_t allocation_size{1024 * 1024 * 1024};

  template <typename OF>
  ControlFlowLog(SectionArg<OF> of) : SectionBase(of.range) {}

  void function_event(EventType evt, uint32_t function_id) {
    uint8_t buffer[6];
    buffer[0] = static_cast<uint8_t>(evt);
    auto used = detail::varint_encode(function_id, &buffer[1]);
    auto total = used + 1;

    if (auto wctx = write(total)) {
      std::copy(&buffer[0], &buffer[total], wctx->mem.begin());
    } else {
      error_exit("Failed to write ", total,
                 " bytes of output to the ControlFlowLog Section.");
    }
  }

  void enter_function(uint32_t function_id) {
    function_event(EnterFunction, function_id);
  }

  void leave_function(uint32_t function_id) {
    function_event(LeaveFunction, function_id);
  }

  void tainted_control_flow(label_t label, uint32_t function_id) {
    // 1 byte event, <= 5 bytes function id, <= 5 bytes label
    uint8_t buffer[11];
    buffer[0] = static_cast<uint8_t>(TaintedControlFlow);
    auto used = detail::varint_encode(function_id, &buffer[1]);
    auto total = used + 1;
    used = detail::varint_encode(label, &buffer[total]);
    total += used;

    if (auto wctx = write(total)) {
      std::copy(&buffer[0], &buffer[total], wctx->mem.begin());
    } else {
      error_exit("Failed to write ", total,
                 " bytes of output to the ControlFlowLog Section.");
    }
  }
};

} // namespace taintdag
