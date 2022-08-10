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
#include <string_view>

namespace taintdag {

namespace {

using offset_t = FnMapping::offset_t;
using length_t = FnMapping::length_t;
using header_t = FnMapping::header_t;
using index_t = FnMapping::index_t;

} // namespace

FnMapping::FnMapping(char *begin, char *end)
    : map_begin(begin), map_end(end), headers_end(map_begin),
      names_begin(map_end) {}

std::optional<offset_t> FnMapping::write_name(std::string_view name) {
  // Write destination
  auto dst{names_begin - name.size()};
  // Check if we have enough space
  if (dst < headers_end) {
    return {};
  }
  // Do the write
  std::copy(name.begin(), name.end(), dst);
  return dst - map_begin;
}

std::optional<offset_t> FnMapping::write_header(header_t header) {
  // Write destination
  auto dst{headers_end};
  // Header end
  auto end{dst + sizeof(header)};
  // Check if we have enough space
  if (end > names_begin) {
    return {};
  }
  // Do the write
  std::memcpy(dst, &header, sizeof(header));
  return dst - map_begin;
}

std::optional<index_t> FnMapping::add_mapping(std::string_view name) {
  // Lock
  std::unique_lock write_lock{write_m};
  // Existing mapping
  if (auto it{mappings.find(name)}; it != mappings.end()) {
    return it->second;
  }
  // New mapping
  auto name_offset{write_name(name)};
  if (!name_offset) {
    return {};
  }
  if (!write_header({*name_offset, length_t(name.size())})) {
    return {};
  }
  names_begin -= name.size();
  headers_end += sizeof(header_t);
  auto result{(headers_end - map_begin) / sizeof(header_t) - 1};
  mappings[{names_begin, name.size()}] = result;
  return result;
}
} // namespace taintdag