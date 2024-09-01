/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/events.h"

namespace taintdag {

void Events::log_fn_event(kind_t kind, Functions::index_t function_id) {
  uint8_t buffer[6];
  buffer[0] = kind;
  auto used = detail::varint_encode(function_id, &buffer[1]);
  auto total = used + 1;

  if (auto wctx = write(total)) {
    std::copy(&buffer[0], &buffer[total], wctx->mem.begin());
  } else {
    error_exit("Failed to write ", total,
               " bytes of output to the ControlFlowLog Section.");
  }
}

void Events::log_cf_event(label_t label, Functions::index_t function_id) {
  // 1 byte event, <= 5 bytes function id, <= 5 bytes label
  uint8_t buffer[11];
  buffer[0] = kind_t::taint;
  auto used = detail::varint_encode(function_id, &buffer[1]);
  auto total = used + 1;
  used = detail::varint_encode(label, &buffer[total]);
  total += used;

  if (auto wctx = write(total)) {
    std::copy(&buffer[0], &buffer[total], wctx->mem.begin());
  } else {
    error_exit("Failed to write ", total,
               " bytes of output to the ControlFlowLog Section.");
  }
}

} // namespace taintdag