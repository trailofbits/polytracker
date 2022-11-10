/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/fnmapping.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <string_view>

namespace taintdag {

namespace {

using index_t = Functions::index_t;

} // namespace

std::optional<index_t> Functions::add_mapping(std::string_view name) {
  // Write `name` into the string table section
  auto maybe_name_offset{string_table.add_string(name)};
  if (!maybe_name_offset) {
    return {};
  }
  // Write a `Function` via `construct`
  auto name_offset{*maybe_name_offset};
  auto maybe_ctx{construct(name_offset)};
  if (!maybe_ctx) {
    return {};
  }
  // Return index of `Function` in `Functions`
  return index(maybe_ctx->t);
}

} // namespace taintdag