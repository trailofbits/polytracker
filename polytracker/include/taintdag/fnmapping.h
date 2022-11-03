/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

#include "taintdag/outputfile.hpp"
#include "taintdag/section.hpp"
#include "taintdag/string_table.hpp"

namespace taintdag {

struct FunctionEntry {
public:
  using offset_t = uint32_t;
  using length_t = uint32_t;
  offset_t name_offset;
  length_t name_len;
};

class Functions : public FixedSizeAlloc<FunctionEntry> {
public:
  using index_t = uint16_t;

  static constexpr uint8_t tag{5};
  static constexpr size_t allocation_size{std::numeric_limits<index_t>::max() *
                                          sizeof(FunctionEntry)};

  template <typename OF>
  Functions(SectionArg<OF> of)
      : FixedSizeAlloc{of.range},
        string_table{of.output_file.template section<StringTable>()} {
    // TODO(hbrodin): Drop the assert, replace with error_exit.
    // assert(of.range.size() <=
    //        std::numeric_limits<index_t>::max() * sizeof(SourceEntry));
    util::dump_range("Functions", of.range);
  }

  std::optional<index_t> add_mapping(std::string_view name);

private:
  StringTable &string_table;
};

} // namespace taintdag
