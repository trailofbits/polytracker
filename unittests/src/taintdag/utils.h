/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "taintdag/taint.hpp"
#include <cstdlib>
#include <random>

namespace taintdag::test {

template <typename T = unsigned long> T rand_limit(T limit) {
  return static_cast<T>(rand()) % limit;
}

inline label_t lbl_inrange(label_t minlabel = 1, label_t maxlabel = max_label) {
  return rand_limit<label_t>(maxlabel - minlabel + 1) + minlabel;
}

// Create a random source taint using values from max_test_* above
inline std::pair<SourceTaint, label_t>
random_source_taint(source_index_t max_source = max_source_index,
                    source_offset_t max_offset = max_source_offset,
                    label_t lblmax = max_label) {
  return {SourceTaint(rand_limit(max_source), rand_limit(max_offset)),
          lbl_inrange(1, lblmax)};
}

// TODO (hbrodin): Analyze the ranges related to maxlbl to ensure it can't go
// out of bounds Create a random union taint using values from max_test_* above
inline std::pair<UnionTaint, label_t>
random_union_taint(label_t maxlbl = max_label) {
  assert((maxlbl <= max_label) &&
         "maxlabel to high to generate random union taint");
  auto l1 = lbl_inrange(1, maxlbl - 2);
  auto l2 = lbl_inrange(1, maxlbl - 2);
  if (l1 == l2)
    l2 += 2;
  else if (l2 == l1 + 1)
    l2++;
  else if (l1 == l2 + 1)
    l1++;

  auto hilbl = std::max(l1, l2);
  return {UnionTaint{l1, l2},
          lbl_inrange(hilbl + 1, std::min(hilbl + 8, max_label))};
}

// Create a random range taint using values from max_test_* above
inline std::pair<RangeTaint, label_t>
random_range_taint(label_t maxlbl = max_label) {
  assert((maxlbl <= max_label) &&
         "maxlabel to high to generate random range taint");
  auto l1 = lbl_inrange(1, maxlbl - 2);
  auto l2 = lbl_inrange(1, maxlbl - 2);
  auto first = std::min(l1, l2);
  auto last = std::max(l1, l2);

  if (first == last)
    last++;
  return {RangeTaint{first, last},
          lbl_inrange(last + 1, std::min(last + 8, max_label))};
}

// Create a random taint value/label pair
inline std::pair<Taint, label_t>
rand_taint(label_t maxlabel = max_label,
           source_index_t max_source = max_source_index,
           source_offset_t max_offset = max_source_offset) {
  auto i = rand_limit(3);
  switch (i) {
  case 0:
    return random_source_taint(max_source, max_offset, maxlabel);
  case 1:
    return random_union_taint(maxlabel);
  default:
    return random_range_taint(maxlabel);
  }
}

// seed random with a 'random' seed and return the seed
inline int init_rand_seed() {
  srand(0xdeadbeef);
  auto seed = rand();
  srand(seed);
  return seed;
}

} // namespace taintdag::test