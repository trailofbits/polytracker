/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <cstddef>
#include <cstdint>

// Separate from control_flow_log.h to avoid duplicate symbol inclusion in
// testing
namespace taintdag {
// For inclusion in the control flow log, we use varint_encode to bit-pack
// each entry. Returns number of bytes required, which is also included in
// the section so that we know entry boundaries.
size_t varint_encode(uint32_t val, uint8_t *buffer);
} // namespace taintdag