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
#include <mutex>

namespace taintdag {

class FnTrace {
public:
  using offset_t = uint32_t;
  using fn_index_t = FnMapping::index_t;

  struct event_t {
    enum class kind_t : uint8_t { entry, exit };
    kind_t kind;
    fn_index_t function;
  };

  FnTrace(char *begin, char *end);
  void log_fn_event(event_t::kind_t kind, fn_index_t idx);
  size_t get_event_count();

private:
  // Trace markers
  char *trace_begin{nullptr};
  char *trace_end{nullptr};
  char *events_end{nullptr};
  // Trace mutex
  std::mutex memory_m;
  // Helpers
  std::optional<offset_t> write_event(event_t event);
};

} // namespace taintdag