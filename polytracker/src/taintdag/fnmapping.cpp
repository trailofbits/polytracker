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

std::optional<index_t> Functions::add_mapping(uint32_t function_id, std::string_view function_name) {
  std::unique_lock mappings_lock(mappings_mutex);

  if (auto it{mappings.find(function_name)}; it != mappings.end()) {
    return it->second;
  }

  std::optional<StringTable::offset_t> maybe_name_offset = string_table.add_string(function_name);
  if (!maybe_name_offset.has_value()) {
    spdlog::error("Could not write function name to strings table");
    return {};
  }

  auto maybe_ctx = construct(Function(maybe_name_offset.value(), function_id));
  if (!maybe_ctx.has_value()) {
    spdlog::error("Could not write Function {0} with id {1:d}, string table ofs {2:d} to the tdag functions section", function_name, function_id, maybe_name_offset.value());
    return {};
  }

  // Return index of the `Function` in `Functions`
  return mappings[function_name] = index(maybe_ctx->t);
}

} // namespace taintdag