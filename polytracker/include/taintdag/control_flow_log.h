/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "taintdag/control_flow_log_encoding.h"
#include "taintdag/outputfile.h"
#include "taintdag/section.h"
#include "taintdag/taint.h"
#include "taintdag/util.h"

namespace taintdag {

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
    auto used = varint_encode(function_id, &buffer[1]);
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
    auto used = varint_encode(function_id, &buffer[1]);
    auto total = used + 1;
    used = varint_encode(label, &buffer[total]);
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
