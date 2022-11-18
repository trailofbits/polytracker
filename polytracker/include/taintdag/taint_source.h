/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <limits>
#include <optional>

#include "taintdag/error.h"
#include "taintdag/section.h"
#include "taintdag/string_table.h"
#include "taintdag/taint.h"

namespace taintdag {

// Holds information about a single taint source. In the current impl
// it is reused to represent sinks as well.
struct SourceEntry {
  // Representing a size that cannot be determined (e.g. for a socket).
  static constexpr uint64_t InvalidSize = ~uint64_t(0);

  // Use this when there is no fd representing this source (e.g. argv)
  static constexpr int InvalidFD = -1;

  // Relative to StringTable memory start
  StringTable::offset_t string_offset;

  // File descriptor currently representing this source.
  int fd;

  // Size of source entry (e.g. file size), use SourceEntry::InvalidSize if not
  // available.
  uint64_t size;

  // Helper to return the name string representing this taint source. The string
  // is stored in a separate StringTable that needs to be passed as argument.
  std::string_view name(StringTable const &st) const {
    return st.from_offset(string_offset);
  }
};

// NOTE(hbrodin): Ideally this would be separated into sources and sinks.
// The issue is that we don't really know until there is a write to a fd
// that it was a sink (even if opened writeable).
// TODO(hbrodin): Consider creating a separate Sinks structure that is used
// when a file is opened for writing (signalling that it could be a sink).
// That would also apply to when creating another bidirectional fd such as
// sockets. For argv or files opened readonly only a source would be created.
struct Sources : public FixedSizeAlloc<SourceEntry> {
  // Index of source, maximum number of sources is limited by this
  using index_t = source_index_t;

  static constexpr uint8_t tag{1};
  static constexpr size_t allocation_size{std::numeric_limits<index_t>::max() *
                                          sizeof(SourceEntry)};

  template <typename OF>
  Sources(SectionArg<OF> of)
      : FixedSizeAlloc{of.range},
        st_{of.output_file.template section<StringTable>()} {
    if (of.range.size() > allocation_size)
      error_exit(
          "Got larger allocation than can be addressed by the index_t type.");
  }

  std::optional<index_t> add_source(std::string_view name,
                                    int fd = SourceEntry::InvalidFD,
                                    uint64_t size = SourceEntry::InvalidSize) {
    // Write source name into the string table section
    if (auto idx = st_.add_string(name); idx) {
      // Source name was successfully written, now add the source to this
      // section.
      if (auto ctx = construct(*idx, fd, size); ctx) {
        return index(ctx->t);
      }
    }
    // Failed to either write string or source.
    return {};
  }

  std::optional<index_t> mapping_idx(int fd) const {
    if (auto ptr = find_reverse_if(
            [fd](SourceEntry const &se) { return se.fd == fd; });
        ptr) {
      return index(*ptr);
    }
    return {};
  }

  // TODO(hbrodin): idx is currently not checked to be within bounds.
  SourceEntry get(index_t idx) { return *(begin() + idx); }

private:
  template <typename F> SourceEntry const *find_reverse_if(F &&f) const {
    auto b = std::make_reverse_iterator(end());
    auto e = std::make_reverse_iterator(begin());
    auto it = std::find_if(b, e, std::forward<F>(f));
    if (it != e) {
      return &*it;
    }
    return {};
  }

  StringTable &st_;
};

} // namespace taintdag
