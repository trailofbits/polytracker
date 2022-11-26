/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <cstdio>
#include <functional>
#include <optional>
#include <span>
#include <string>

#include "taintdag/taint.h"

namespace util {
template <typename T, typename Tuple> struct TypeIndex;

// Determines the index of a type T in a Tuple
template <typename T, typename... Types>
struct TypeIndex<T, std::tuple<Types...>> {
  static constexpr std::size_t index = []() {
    constexpr std::array<bool, sizeof...(Types)> eq{
        {(std::is_same_v<Types, T>)...}};
    const auto it = std::find(eq.begin(), eq.end(), true);
    if (it == eq.end())
      std::runtime_error("Type is not in type sequnce");
    return std::distance(eq.begin(), it);
  }();
};

inline void dump_range(std::string name, std::span<uint8_t> range) {
  auto begin = reinterpret_cast<uintptr_t>(&*range.begin());
  auto end = reinterpret_cast<uintptr_t>(&*range.end());
  printf("Name: %s begin: %lx end: %lx\n", name.data(), begin, end);
}

// Unify length from various read operations to a single type
//
// This type will only expose the length in `value` if it is valid.
// It is only valid (within taint context) if it is > 0
struct Length {
  // Default constructor, produces an invalid Length
  Length() = default;

  // Constructs a Length from a return value of ssize_t,
  // where >0 produces valid lengths
  static Length from_returned_size(ssize_t retval);

  // Construct a Length from a number of items and each items size.
  static Length from_returned_size_count(size_t size, size_t nitems);

  // Construct a Length from a resulting string.
  static Length from_returned_string(char const *str);

  // The computed value
  std::optional<size_t> const &value() const;

  // If the length is valid
  bool valid() const;

private:
  Length(size_t value);

  std::optional<size_t> value_;
};

// Unify offset from various read operations to a single type
//
// This type will only expose the offset in `value` if it is valid.
struct Offset {
  // Default constructor, produces an invalid Offset
  Offset() = default;

  // Constructs an Offset from a file descriptor (int)
  static Offset from_fd(int fd);

  // Constructs an Offset from a file descriptor (FILE*)
  static Offset from_file(FILE *file);

  // Returns an Offset object from an off_t value
  // NOTE: the Offset returned might be invalid depending on offset_value.
  static Offset from_off_t(off_t offset_value);

  // The computed value
  std::optional<taintdag::source_offset_t> const &value() const;

  // If the offset is valid
  bool valid() const;

private:
  Offset(off_t value);

  std::optional<taintdag::source_offset_t> value_;
};
} // namespace util
