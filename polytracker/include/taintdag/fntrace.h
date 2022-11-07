/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "taintdag/fnmapping.h"

#include <cstdint>

namespace taintdag {

struct Event {
public:
  enum class kind_t : uint8_t { entry, exit };
  kind_t kind;
  Functions::index_t function;
};

class Events : public FixedSizeAlloc<Event> {
public:
  static constexpr uint8_t tag{6};
  static constexpr size_t allocation_size{std::numeric_limits<uint32_t>::max() *
                                          sizeof(Event)};

  template <typename OF> Events(SectionArg<OF> of) : FixedSizeAlloc{of.range} {}
  void log_fn_event(Event::kind_t kind, Functions::index_t idx);
};

} // namespace taintdag