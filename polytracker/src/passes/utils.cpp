/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "polytracker/passes/utils.h"

#include <cstddef>
#include <llvm/ADT/StringRef.h>

#include <spdlog/spdlog.h>

#include <fstream>

namespace polytracker {

str_set_t readIgnoreLists(const str_vec_t &paths) {
  str_set_t result;
  for (auto &path : paths) {
    std::ifstream fs(path);
    if (!fs.is_open()) {
      spdlog::error("Could not read: {}", path);
      continue;
    }
    // read file line-by-line
    for (std::string line; std::getline(fs, line);) {
      llvm::StringRef ref(line);
      // ignoring comments and empty lines
      if (ref.startswith("#") || ref == "\n") {
        continue;
      }
      // ignore `main`
      if (ref.contains("main")) {
        continue;
      }
      // process line with `discard` only
      if (!ref.contains("discard")) {
        continue;
      }
      // function name is between ':' and '='
      constexpr auto npos = llvm::StringRef::npos;
      auto s{ref.find(':')};
      auto e{ref.find('=')};
      if (s != npos && e != npos && s + 1 < e) {
        result.insert(ref.slice(s + 1, e).str());
      }
    }
  }
  return result;
}

} // namespace polytracker