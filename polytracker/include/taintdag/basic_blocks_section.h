
/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "outputfile.h"
#include "taintdag/section.h"
#include "taintdag/taint.h"
#include "taintdag/util.h"

#include <cstdint>

namespace taintdag {

// This is a very limited form of basic blocks log
// 1. disregards any threads, assuming everything is single threaded
// 2. it stores entered blocks naively
// 3. current basic block is the last block without considering what thread
// caller is on.
struct BasicBlocksLog : public FixedSizeAlloc<uint32_t> {

  static constexpr uint8_t tag{9};

  // Room for 1024*1024 basic blocks
  static constexpr size_t allocation_size{0x100000 * sizeof(uint32_t)};

  template <typename OF>
  BasicBlocksLog(SectionArg<OF> of) : FixedSizeAlloc{of.range} {}

  // Record that `label` affected control flow.
  void record(uint32_t block_index) {
    if (!construct(block_index)) {
      error_exit("Failed to basic block index", block_index);
    }
    current_block_index = block_index;
    // TODO(hbrodin): Consider storing a pair: (basic_block_index, count),
    // variable length encoded. that way less storage would be required,
    // especially in the precense of tight loops (well, maybe at least)
  }

  uint32_t current_block_index{std::numeric_limits<uint32_t>::max()};
};
} // namespace taintdag