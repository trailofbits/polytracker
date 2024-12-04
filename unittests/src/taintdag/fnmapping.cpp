/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/fnmapping.h"

#include <catch2/catch.hpp>

TEST_CASE("Test fnmapping operations") {
  namespace td = taintdag;
  SECTION("Add unique functions, functions are successfully inserted") {
    td::OutputFile<td::StringTable, td::Functions> of{std::tmpnam(nullptr)};
    auto &functions{of.section<td::Functions>()};
    REQUIRE(functions.add_mapping(4, "foo"));
    REQUIRE(functions.add_mapping(55, "bar"));
    REQUIRE(functions.add_mapping(1, "baz"));
  }

  SECTION("Add unique functions, functions have successive indices") {
    td::OutputFile<td::StringTable, td::Functions> of{std::tmpnam(nullptr)};
    auto &functions{of.section<td::Functions>()};
    REQUIRE(functions.add_mapping(4, "foo").value_or(3) == 0);
    REQUIRE(functions.add_mapping(55, "bar").value_or(3) == 1);
    REQUIRE(functions.add_mapping(1, "baz").value_or(3) == 2);
  }

  SECTION("Add duplicate functions, duplicate functions have the same index") {
    td::OutputFile<td::StringTable, td::Functions> of{std::tmpnam(nullptr)};
    auto &functions{of.section<td::Functions>()};
    auto foo_1{functions.add_mapping(4, "foo").value_or(3)};
    functions.add_mapping(55, "bar");
    functions.add_mapping(1, "baz");
    auto foo_2{functions.add_mapping(4, "foo").value_or(4)};
    REQUIRE(foo_1 == foo_2);
  }
}