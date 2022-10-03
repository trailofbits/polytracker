/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <string>
#include <unordered_set>
#include <vector>

namespace polytracker {
using str_set_t = std::unordered_set<std::string>;
using str_vec_t = std::vector<std::string>;

str_set_t readIgnoreLists(const str_vec_t &paths);
} // namespace polytracker