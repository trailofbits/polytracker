/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/fntrace.h"

#include <cstring>

#include "taintdag/error.h"

namespace taintdag {

namespace {

using offset_t = FnTrace::offset_t;
using fn_index_t = FnMapping::index_t;

} // namespace

FnTrace::FnTrace(char *begin, char *end)
    : trace_begin(begin), trace_end(end), events_end(trace_begin) {}

std::optional<offset_t> FnTrace::write_event(event_t event) {
  auto dst{events_end};
  auto end{events_end + sizeof(event_t)};
  if (end > trace_end) {
    return {};
  }
  std::memcpy(dst, &event, sizeof(event_t));
  return dst - trace_begin;
}

size_t FnTrace::get_event_count() {
  return (events_end - trace_begin) / sizeof(event_t);
}

void FnTrace::log_fn_event(event_t::kind_t kind, fn_index_t idx) {
  std::unique_lock write_lock{memory_m};
  auto maybe_offset{write_event({kind, idx})};
  if (!maybe_offset) {
    error_exit("Failed to log event with id: ", get_event_count());
  }
  events_end += sizeof(event_t);
}

} // namespace taintdag