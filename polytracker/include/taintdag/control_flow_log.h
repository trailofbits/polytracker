
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

using control_flow_log_type = std::pair<label_t, uint32_t>;
struct ControlFlowLog
    : public FixedSizeAlloc<control_flow_log_type> {

  static constexpr uint8_t tag{8};

  // Room for 1024*1024 * labels
  static constexpr size_t allocation_size{0x100000 *
                                          sizeof(control_flow_log_type)};

  template <typename OF>
  ControlFlowLog(SectionArg<OF> of)
      : FixedSizeAlloc{of.range},
        bblog_{of.output_file.template section<BasicBlocksLog>()} {}

  // Record that `label` affected control flow.
  void record(label_t label) {
    auto current_bb = bblog_.current_block_index;
    if (!construct(std::make_pair(label, current_bb))) {
        error_exit("Failed to record label ", label,
                   " as affecting control flow");
      }
  }


  BasicBlocksLog& bblog_;
  };
} // namespace taintdag