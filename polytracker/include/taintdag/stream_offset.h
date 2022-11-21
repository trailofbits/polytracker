/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <array>
#include <atomic>

#include "taintdag/error.h"
#include "taintdag/taint.h"

namespace taintdag {

// Helper class that tracks reads per source for a predetermined number of
// sources, controlled by SourceCount.
template <size_t SourceCount> class StreamOffset {
public:
  // Records a read of len bytes from the source at index idx. Returns the
  // sequential offset.
  // NOTE: Uses atomic fetch-add to update the offsets. It is assumed that
  // concurrent read operations for the same source is the result of invalid
  // code. Reads on the same source should be protected from running in
  // parallell (at least for the taint sources considered here, e.g. files).
  source_offset_t increase(source_index_t idx, size_t len) {
    if (idx >= SourceCount)
      error_exit("Attempted increase offset of source index ",
                 static_cast<uint64_t>(idx), ", only ", SourceCount,
                 " sources available");
    return offset[idx].fetch_add(len);
  }

private:
  using atomic_t = std::atomic<source_offset_t>;
  std::array<atomic_t, SourceCount> offset{0};
};

} // namespace taintdag