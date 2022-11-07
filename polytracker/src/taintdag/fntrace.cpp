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

using fn_index_t = Functions::index_t;

} // namespace

void Events::log_fn_event(Event::kind_t kind, Functions::index_t idx) {
  // Write an `Event` via `construct`
  auto maybe_ctx{construct(kind, idx)};
  if (!maybe_ctx) {
    error_exit("Failed to log event with id: ", count());
  }
}

} // namespace taintdag