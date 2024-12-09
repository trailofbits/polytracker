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
using offset_t = Function::offset_t;

} // namespace

/* Maps to the function names recorded in the strings section, from
*  the function IDs recorded in cflog entry callstacks.
*  This section should look like this:
*  |offset|id|offset|id|...
*/
std::optional<index_t> Functions::add_mapping(uint32_t function_id, std::string_view function_name) {
  // Lock `mappings`
  std::unique_lock mappings_lock(mappings_mutex);
  // See if we already have a mapping
  if (auto it{mappings.find(function_id)}; it != mappings.end()) {
    return it->second;
  }
  // Write `name` into the string table section
  auto maybe_name_offset{string_table.add_string(function_name)};
  if (!maybe_name_offset) {
    return {};
  }

  offset_t name_offset{*maybe_name_offset};
  auto maybe_offset_ctx{construct(name_offset)};
  if (!maybe_offset_ctx) {
    return {};
  }

  auto maybe_fn_ctx{construct((offset_t)function_id)};
  if (!maybe_fn_ctx) {
    return {};
  }

  // Keep the function_id to offset mapping so we can check for it later
  return mappings[function_id] = index(maybe_offset_ctx->t);
}

} // namespace taintdag