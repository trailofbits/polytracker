/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <cstdint>
#include <mutex>
#include <optional>
#include <string_view>
#include <unordered_map>

namespace taintdag {

class FnMapping {
public:
  using offset_t = uint32_t;
  using length_t = uint32_t;

  struct header_t {
    offset_t name_offset;
    length_t name_len;
  };

  using index_t = uint16_t;

  FnMapping(char *begin, char *end);
  std::optional<index_t> add_mapping(std::string_view name);
  size_t get_mapping_count();

private:
  // Map markers
  char *map_begin{nullptr};
  char *map_end{nullptr};
  char *headers_end{nullptr};
  char *names_begin{nullptr};
  // Map mutex
  std::mutex map_m;
  // Helpers
  std::optional<offset_t> write_name(std::string_view name);
  std::optional<offset_t> write_header(header_t header);
  // Cache
  std::unordered_map<std::string_view, index_t> mappings;
};

} // namespace taintdag