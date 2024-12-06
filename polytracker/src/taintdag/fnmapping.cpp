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

// The goal here is to get to the following state:
//  - the cflog section contains function ids
//  - the functions section maps those function ids to the offsets of names in the strings table
//  - the strings table contains names
// In this way, the functions section is a lookup layer for getting names (in their original, mangled format - you can demangle them later with cxxfilt in python) out of the strings table.
std::optional<index_t> Functions::add_mapping(uint32_t function_id, std::string_view function_name) {
  // Lock `mappings`
  std::unique_lock mappings_lock(mappings_mutex);
  // See if we already have a mapping of the function id
  if (auto it{mappings.find(function_id)}; it != mappings.end()) {
    return it->second;
  }
  // Write the function's mangled name into the string table section
  auto maybe_name_offset{string_table.add_string(function_name)};
  if (!maybe_name_offset) {
    return {};
  }
  // Now write the function ID into the functions section
  auto maybe_fn_id_ctx{construct((offset_t) function_id)};
  if (!maybe_fn_id_ctx) {
    return {};
  }

  // Finally, write the offset in the string table of the function name into the functions section
  auto name_offset{*maybe_name_offset};
  auto maybe_ctx{construct(name_offset)};
  if (!maybe_ctx) {
    return {};
  }
  // Return index of `Function` in `Functions`
  return mappings[function_id] = index(maybe_ctx->t);
}

} // namespace taintdag