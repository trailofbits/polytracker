/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <spdlog/spdlog.h>

#include <cstdlib>
#include <sstream>

namespace taintdag {

template <typename... Msgs> void error_exit(Msgs &&... msgs) {
  std::stringstream ss;
  (ss << ... << msgs);
  spdlog::error(ss.str());
  std::exit(EXIT_FAILURE);
}

} // namespace taintdag