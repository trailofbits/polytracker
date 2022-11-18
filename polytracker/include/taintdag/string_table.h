/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <concepts>
#include <iterator>
#include <limits>

#include "taintdag/error.h"
#include "taintdag/section.h"
#include "taintdag/util.h"

namespace taintdag {

template <typename OffsetT = uint32_t, typename LengthT = uint16_t,
          uint8_t Tag = 3, size_t AllocationSize = 0x100000>
struct StringTableBase : public SectionBase {
  using offset_t = OffsetT;
  using length_t = LengthT;

  static_assert(sizeof(length_t) <= sizeof(offset_t),
                "offset_t should be larger than or equal to length_t");

  static constexpr size_t max_offset = std::numeric_limits<offset_t>::max();

  // Max string length is limited by either length-type or by maximum offset
  // that can be expressed.
  static constexpr size_t max_string_len =
      std::min(static_cast<size_t>(std::numeric_limits<length_t>::max()),
               max_offset - sizeof(length_t));

  static constexpr uint8_t tag{Tag};
  static constexpr size_t allocation_size{AllocationSize};
  static constexpr size_t align_of = alignof(length_t);

  template <typename OF>
  StringTableBase(SectionArg<OF> of) : SectionBase{of.range} {
    if (of.range.size() > max_offset) {
      error_exit("Tried to use an allocation of size ", of.range.size(),
                 " max in current offset_t config is ", max_offset);
    }
  }

  // Appends the string `sv` to the string table.
  // Returns the offset of the string entry. Note that this is not the
  // string, but the offset to the size of it. Recover the string
  // by using `from_offset`.
  std::optional<offset_t> add_string(std::string_view sv) {
    if (sv.size() > max_string_len) {
      error_exit("Tried to store a string of size ", sv.size(), " max is ",
                 max_string_len);
      // Doesn't return from here.
    }

    auto len = allocated_len(sv.size());
    if (auto write_context = write(len)) {
      // prefix with length
      *reinterpret_cast<length_t *>(&*(write_context->mem.begin())) = sv.size();

      // copy string
      std::copy(sv.begin(), sv.end(),
                write_context->mem.begin() + sizeof(length_t));
      return offset(write_context->mem.begin());
    }
    // Failed to allocate space for string
    return {};
  }

  // Returns a string from it's offset. Offset is typically returned from
  // add_string().
  std::string_view from_offset(offset_t ofs) const {
    return *iterator{mem_.begin() + ofs};
  }

  // Provides forward iteration of stored strings
  struct iterator {
    using difference_type =
        int64_t; // TODO(hbrodin): What is the correct type to use here?
    using value_type = std::string_view;

    bool operator==(iterator const &o) const { return it_ == o.it_; }

    iterator &operator++() {
      advance();
      return *this;
    }

    iterator operator++(int) {
      auto res = *this;
      advance();
      return res;
    }

    value_type operator*() const {
      return value_type{
          reinterpret_cast<char const *>(&*it_ + sizeof(length_t)), curr_len()};
    }

    iterator() {}
    iterator(SectionBase::span_t::iterator it) : it_{it} {}

  private:
    void advance() { it_ += allocated_len(curr_len()); }

    // Reads the len from the buffer
    length_t curr_len() const {
      return *reinterpret_cast<length_t const *>(&*it_);
    }

    SectionBase::span_t::iterator it_;
  };

  // NOTE(hbrodin): Requires more modern version to compile. Not stricly needed.
  // static_assert(std::forward_iterator<iterator>);

  iterator begin() const { return iterator{mem_.begin()}; }

  iterator end() const { return iterator{mem_.begin() + size()}; }

private:
  // Returns the required allocated, aligned len for a string of length len
  // includes the required storage for length_t.
  static size_t allocated_len(size_t len) {
    auto req = len + sizeof(length_t);
    if (auto rem = req % align_of; rem != 0) {
      req += align_of - rem;
    }
    return req;
  }
};

using StringTable = StringTableBase<>;

} // namespace taintdag
