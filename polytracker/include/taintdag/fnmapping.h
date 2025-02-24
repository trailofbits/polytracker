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

#include "taintdag/outputfile.h"
#include "taintdag/section.h"
#include "taintdag/string_table.h"

namespace taintdag {

struct Function {
  using offset_t = StringTable::offset_t;
  offset_t name_offset;
  uint32_t function_id;

  Function(offset_t name_ofs, uint32_t f_id) :
    name_offset(name_ofs), function_id(f_id) {};
};

class Functions : public FixedSizeAlloc<Function> {
public:
  using index_t = StringTable::offset_t;

  static constexpr uint8_t tag{6};
  static constexpr size_t allocation_size{std::numeric_limits<index_t>::max() *
                                          sizeof(Function)};

  template <typename OF>
  Functions(SectionArg<OF> of)
      : FixedSizeAlloc{of.range},
        string_table{of.output_file.template section<StringTable>()} {}

  std::optional<index_t> add_mapping(uint32_t function_id, std::string_view function_name);

private:
  StringTable &string_table;
  std::mutex mappings_mutex;
  // look up Function index in the Functions section by function name
  std::unordered_map<std::string_view, index_t> mappings;
};

} // namespace taintdag
