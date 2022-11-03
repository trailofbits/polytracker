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

// TODO(hbrodin): Currently using this as a workaround to be able to compile
// this file as part of FunctionTracingPass.
#if __cpp_concepts
#if __cpp_lib_concepts
#include "taintdag/outputfile.hpp"
#include "taintdag/section.hpp"
#include "taintdag/string_table.hpp"
#endif
#endif

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
  std::mutex memory_m;
  // Helpers
  std::optional<offset_t> write_name(std::string_view name);
  std::optional<offset_t> write_header(header_t header);
  // Cache
  std::unordered_map<std::string_view, index_t> mappings;
};

// TODO (hbrodin): Unsure what goes in the FunctionEntry atm.
struct FunctionEntry {};

// TODO(hbrodin): Currently using this as a workaround to be able to compile
// this file as part of FunctionTracingPass.
#if __cpp_concepts
#if __cpp_lib_concepts
struct Functions : public FixedSizeAlloc<FunctionEntry> {
  template <typename OF>
  Functions(SectionArg<OF> of)
      : FixedSizeAlloc{of.range},
        st_{of.output_file.template section<StringTable>()} {
    // TODO(hbrodin): Drop the assert, replace with error_exit.
    // assert(of.range.size() <=
    //        std::numeric_limits<index_t>::max() * sizeof(SourceEntry));
    util::dump_range("Functions", of.range);
  }

  StringTable &st_;
};
#endif
#endif
} // namespace taintdag