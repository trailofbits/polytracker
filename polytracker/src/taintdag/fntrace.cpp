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

void Events::log_fn_event(Event::kind_t kind, Functions::index_t idx) {
  // Write an `Event` via `construct`
  if (!construct(kind, idx)) {
    error_exit("Failed to log event with id: ", count());
  }
}

} // namespace taintdag