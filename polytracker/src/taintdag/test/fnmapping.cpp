/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/fnmapping.h"

#include <catch2/catch.hpp>

#include <array>

TEST_CASE("Test fnmapping operations") {
  SECTION("Add unique functions, functions are successfully inserted") {
    std::array<char, 128> storage;
    taintdag::FnMapping fnm(&*storage.begin(), &*storage.end());
    REQUIRE(fnm.add_mapping("foo"));
    REQUIRE(fnm.add_mapping("bar"));
    REQUIRE(fnm.add_mapping("baz"));
  }

  SECTION("Add unique functions, functions have successive indices") {
    std::array<char, 128> storage;
    taintdag::FnMapping fnm(&*storage.begin(), &*storage.end());
    REQUIRE(fnm.add_mapping("foo").value_or(3) == 0);
    REQUIRE(fnm.add_mapping("bar").value_or(3) == 1);
    REQUIRE(fnm.add_mapping("baz").value_or(3) == 2);
  }

  SECTION("Add duplicate functions, duplicate functions have the same index") {
    std::array<char, 128> storage;
    taintdag::FnMapping fnm(&*storage.begin(), &*storage.end());
    auto foo_1{fnm.add_mapping("foo").value_or(3)};
    fnm.add_mapping("bar");
    fnm.add_mapping("baz");
    auto foo_2{fnm.add_mapping("foo").value_or(3)};
    REQUIRE(foo_1 == foo_2);
  }
}