
/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "taintdag/section.h"
#include "taintdag/taint.h"
#include "taintdag/util.h"

namespace taintdag {

struct ControlFlowLog : public FixedSizeAlloc<label_t> {

  static constexpr uint8_t tag{8};

  // Room for 1024*1024 * labels
  static constexpr size_t allocation_size{0x100000 * sizeof(label_t)};

  template <typename OF>
  ControlFlowLog(SectionArg<OF> of) : FixedSizeAlloc{of.range} {}

  // Record that `label` affected control flow.
  void record(label_t label) {
    if (!construct(label)) {
      error_exit("Failed to record label ", label,
                 " as affecting control flow");
    }
  }
};
} // namespace taintdag