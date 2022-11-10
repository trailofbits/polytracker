/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/fntrace.h"

#include <catch2/catch.hpp>

TEST_CASE("Test fntrace operations") {
  namespace td = taintdag;
  SECTION("Log unique events") {
    td::OutputFile<td::Events> of{std::tmpnam(nullptr)};
    auto &events{of.section<td::Events>()};
    td::Functions::index_t fnidx{0};
    events.log_fn_event(td::Event::kind_t::entry, fnidx);
    events.log_fn_event(td::Event::kind_t::exit, fnidx);
    SECTION("Events are successfully written") {
      REQUIRE(events.count() == 2);
      td::Event entry{*events.begin()};
      REQUIRE(entry.kind == td::Event::kind_t::entry);
      REQUIRE(entry.function == fnidx);
      td::Event exit{*(events.begin() + 1)};
      REQUIRE(exit.kind == td::Event::kind_t::exit);
      REQUIRE(exit.function == fnidx);
    }
  }
}