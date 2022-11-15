/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <spdlog/spdlog.h>

#include <functional>
#include <sstream>

namespace taintdag {

extern std::function<void(int)> error_function;

template <typename... Msgs> void error_exit(Msgs &&... msgs) {
  std::stringstream ss;
  (ss << ... << msgs);
  spdlog::error(ss.str());
  error_function(-1);
}
} // namespace taintdag
