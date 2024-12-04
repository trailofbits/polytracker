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
public:
  using offset_t = StringTable::offset_t;
  offset_t name_offset;
};

class Functions : public FixedSizeAlloc<Function> {
public:
  using index_t = uint16_t;

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
  std::unordered_map<uint32_t, index_t> mappings;
};

} // namespace taintdag
