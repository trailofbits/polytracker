
/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include "taintdag/events.h"
#include "taintdag/section.h"
#include <catch2/catch.hpp>

TEST_CASE("Simple varint encoding") {
  using namespace taintdag::detail;
  uint8_t buffer[5];

  SECTION("Encode 0") {
    auto n = varint_encode(0, buffer);
    REQUIRE(n == 1);
    REQUIRE(buffer[0] == 0);
  }

  SECTION("Encode 1") {
    auto n = varint_encode(1, buffer);
    REQUIRE(n == 1);
    REQUIRE(buffer[0] == 1);
  }

  SECTION("Encode 0x7f") {
    auto n = varint_encode(0x7f, buffer);
    REQUIRE(n == 1);
    REQUIRE(buffer[0] == 0x7f);
  }

  SECTION("Encode 0x80") {
    auto n = varint_encode(0x80, buffer);
    REQUIRE(n == 2);
    REQUIRE(buffer[0] == 0x80);
    REQUIRE(buffer[1] == 0x01);
  }
  SECTION("Encode 0x3ffe") {
    auto n = varint_encode(0x3ffe, buffer);
    REQUIRE(n == 2);
    REQUIRE(buffer[0] == 0xfe);
    REQUIRE(buffer[1] == 0x7f);
  }
  SECTION("Encode 0xffffffff") {
    auto n = varint_encode(0xffffffff, buffer);
    REQUIRE(n == 5);
    REQUIRE(buffer[0] == 0xff);
    REQUIRE(buffer[1] == 0xff);
    REQUIRE(buffer[2] == 0xff);
    REQUIRE(buffer[3] == 0xff);
    REQUIRE(buffer[4] == 0x0f);
  }
}

// TEST_CASE("Test events section operations") {
//   namespace td = taintdag;
//   SECTION("Log unique events") {
//     td::OutputFile<td::Events> of{std::tmpnam(nullptr)};
//     auto &events{of.section<td::Events>()};
//     td::Functions::index_t fnidx{0};
//     events.log_fn_event(td::Events::kind_t::entry, fnidx);
//     events.log_fn_event(td::Events::kind_t::exit, fnidx);
//     SECTION("Events are successfully written") {
//       td::Events entry{*events.begin()};
//       REQUIRE(entry.kind == td::Events::kind_t::entry);
//       REQUIRE(entry.function == fnidx);
//       td::Events exit{*(events.begin() + 1)};
//       REQUIRE(exit.kind == td::Events::kind_t::exit);
//       REQUIRE(exit.function == fnidx);
//     }
//   }
// }
