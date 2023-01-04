/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/fnmapping.h"

#include <string_view>
#include <iostream>

namespace taintdag {

namespace {

using index_t = Functions::index_t;

} // namespace

std::optional<index_t> Functions::add_mapping(std::string_view name) {
  // Lock `mappings`
  std::cout << "BREAK 1" << std::endl;
  std::unique_lock mappings_lock(mappings_mutex);
  std::cout << "BREAK 2" << std::endl;
  // See if we already have a mapping of `name`
  if (auto it{mappings.find(name)}; it != mappings.end()) {
    return it->second;
  }
  std::cout << "BREAK 3" << std::endl;
  // Write `name` into the string table section
  auto maybe_name_offset{string_table.add_string(name)};
  std::cout << "BREAK 4" << std::endl;
  if (!maybe_name_offset) {
    return {};
  }
  // Write a `Function` via `construct`
  std::cout << "BREAK 5" << std::endl;
  auto name_offset{*maybe_name_offset};
  auto maybe_ctx{construct(name_offset)};
  std::cout << "BREAK 6" << std::endl;
  if (!maybe_ctx) {
    return {};
  }
  std::cout << "BREAK 7" << std::endl;
  // Return index of `Function` in `Functions`
  std::cout << "BREAK 8" << std::endl;
  mappings[name] = index(maybe_ctx->t);
  std::cout << "BREAK 9" << std::endl;
  return mappings[name];
}

} // namespace taintdag