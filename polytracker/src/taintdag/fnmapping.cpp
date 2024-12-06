/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/fnmapping.h"

#include <iostream>
#include <string_view>

namespace taintdag {

namespace {

using index_t = Functions::index_t;

} // namespace

/* Maps to the function names recorded in the strings section, from
*  the function IDs recorded in cflog entry callstacks.
*/
std::optional<index_t> Functions::add_mapping(uint32_t function_id, std::string_view function_name) {
  // Lock `mappings`
  // std::cout << "BREAK 1" << std::endl;
  std::unique_lock mappings_lock(mappings_mutex);
  // See if we already have a mapping of `name`
  if (auto it{mappings.find(function_id)}; it != mappings.end()) {
    return it->second;
  }
  // Write `name` into the string table section
  auto maybe_name_offset{string_table.add_string(function_name)};
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
  return mappings[function_id] = index(maybe_ctx->t);
}

} // namespace taintdag