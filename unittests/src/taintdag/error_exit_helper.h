/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "taintdag/error.h"
namespace taintdag {

struct ErrorExit {};

inline void throwing_error_function(int) { throw ErrorExit{}; }

struct ErrorExitReplace {
  std::function<void(int)> old;
  ErrorExitReplace()
      : old{std::exchange(error_function, throwing_error_function)} {}
  ~ErrorExitReplace() { error_function = old; }
};
}