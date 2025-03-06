/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <catch2/catch.hpp>
#include <stdlib.h>

#include "taintdag/section.h"

#include "utils.h"

namespace taintdag {
TEST_CASE("SectionBase operations are consistent", "[SectionBase]") {

  // To be able to capture error_exits
  test::ErrorExitReplace errthrow;

  // Exposing the members of SectionBase
  struct TestSectionBase : public SectionBase {
    TestSectionBase(span_t t) : SectionBase{t} {}

    auto write(size_t s) { return SectionBase::write(s); }

    auto offset(SectionBase::span_t::iterator o) {
      return SectionBase::offset(o);
    }

    auto offset(uint8_t const *p) { return SectionBase::offset(p); }
  };

  std::uint8_t backing[64];
  TestSectionBase sb{backing};
  SectionBase::span_t last;

  REQUIRE(sb.size() == 0);

  // Allocate 1 byte
  {
    auto ctx = sb.write(1);
    REQUIRE(ctx);
    last = ctx->mem;
  }
  REQUIRE(sb.size() == 1);
  REQUIRE(sb.offset(last.begin()) == 0);
  REQUIRE(sb.offset(&*last.begin()) == 0);
  REQUIRE(last.size() == 1);

  // Allocate remainder but 1 byte
  auto n = sizeof(backing) - 2;
  {
    auto ctx = sb.write(n);
    REQUIRE(ctx);
    // Allocation is compact
    REQUIRE(ctx->mem.begin() == last.end());
    last = ctx->mem;
  }

  REQUIRE(sb.size() == n + 1);
  REQUIRE(sb.offset(last.begin()) == 1);
  REQUIRE(sb.offset(&*last.begin()) == 1);
  REQUIRE(last.size() == n);

  // Allocate last byte
  {
    auto ctx = sb.write(1);
    REQUIRE(ctx);
    // Allocation is compact
    REQUIRE(ctx->mem.begin() == last.end());
    last = ctx->mem;
  }

  REQUIRE(sb.size() == n + 1 + 1);
  REQUIRE(sb.offset(last.begin()) == n + 1);
  REQUIRE(sb.offset(&*last.begin()) == n + 1);
  REQUIRE(last.size() == 1);

  // Attempt additional allocation, should fail.
  auto ctx = sb.write(1);
  REQUIRE(!ctx);

  // If offset is requested for out of bounds memory, just abort. Something
  // is seriously wrong.
  REQUIRE_THROWS_AS(sb.offset(SectionBase::span_t::iterator{}),
                    test::ErrorExit);
  REQUIRE_THROWS_AS(sb.offset(last.end()), test::ErrorExit);

  REQUIRE_THROWS_AS(sb.offset(static_cast<uint8_t const *>(nullptr)),
                    test::ErrorExit);
  REQUIRE_THROWS_AS(
      sb.offset(reinterpret_cast<uint8_t const *>(&backing + sizeof(backing))),
      test::ErrorExit);
}

TEST_CASE("FixedSizeAlloc operations are consistent", "[FixedSizeAlloc]") {

  // To be able to capture error_exits
  test::ErrorExitReplace errthrow;

  struct Dummy {
    int32_t i;
    char c;

    Dummy(int32_t ii, char cc) : i{ii}, c{cc} {}
  };

  // Assumptions for the test case.
  REQUIRE(alignof(Dummy) == 4);
  REQUIRE(sizeof(Dummy) == 8);

  using Section = FixedSizeAlloc<Dummy>;

  const size_t backing_count = 3;
  const size_t backing_bytes = backing_count * sizeof(Dummy);

  // To ensure we get correct alignment of the backing
  alignas(Dummy) std::uint8_t backing[backing_bytes];
  Section s{backing};

  REQUIRE(s.entry_size() == sizeof(Dummy));
  REQUIRE(s.align_of == alignof(Dummy));
  REQUIRE(s.size() == 0);
  REQUIRE(s.count() == 0);
  REQUIRE(s.begin() == s.end());

  SECTION("Adding instances affect size, count and constructed instance is "
          "available") {
    // Can add first entry
    {
      auto ctx = s.construct(999, 'A');
      REQUIRE(ctx);
      REQUIRE(ctx->t.i == 999);
      REQUIRE(ctx->t.c == 'A');
      REQUIRE(s.index(ctx->t) == 0);
    }
    REQUIRE(s.count() == 1);
    REQUIRE(s.size() == sizeof(Dummy));

    // Can add when there is already an entry but not full.
    {
      auto ctx = s.construct(33, 'B');
      REQUIRE(ctx);
      REQUIRE(ctx->t.i == 33);
      REQUIRE(ctx->t.c == 'B');
      REQUIRE(s.index(ctx->t) == 1);
    }
    REQUIRE(s.count() == 2);
    REQUIRE(s.size() == 2 * sizeof(Dummy));

    // Can fill the backing store with entries
    {
      auto ctx = s.construct(-1, 'C');
      REQUIRE(ctx);
      REQUIRE(ctx->t.i == -1);
      REQUIRE(ctx->t.c == 'C');
      REQUIRE(s.index(ctx->t) == 2);
    }
    REQUIRE(s.count() == 3);
    REQUIRE(s.size() == 3 * sizeof(Dummy));

    // Can't insert beyound capacity
    auto ctx = s.construct(-5, 'D');
    REQUIRE(!ctx);
  }

  SECTION("Require aligned construction") {
    SectionBase::span_t b1{&backing[1], sizeof(backing) - 7};
    REQUIRE_THROWS_AS(Section{b1}, test::ErrorExit);

    SectionBase::span_t b2{&backing[2], sizeof(backing) - 6};
    REQUIRE_THROWS_AS(Section{b2}, test::ErrorExit);

    SectionBase::span_t b3{&backing[3], sizeof(backing) - 5};
    REQUIRE_THROWS_AS(Section{b3}, test::ErrorExit);
  }

  SECTION("Require size to be a multiple of align_of") {
    SectionBase::span_t b1{&backing[0], sizeof(backing) - 1};
    REQUIRE_THROWS_AS(Section{b1}, test::ErrorExit);

    SectionBase::span_t b2{&backing[0], sizeof(backing) - 2};
    REQUIRE_THROWS_AS(Section{b2}, test::ErrorExit);

    SectionBase::span_t b3{&backing[0], sizeof(backing) - 3};
    REQUIRE_THROWS_AS(Section{b3}, test::ErrorExit);
  }

  SECTION("Iteration") {
    s.construct(-1, 'a');
    REQUIRE(std::distance(s.begin(), s.end()) == 1);
    s.construct(-2, 'b');
    REQUIRE(std::distance(s.begin(), s.end()) == 2);
    s.construct(-3, 'c');
    REQUIRE(std::distance(s.begin(), s.end()) == 3);

    // Know that begin is valid due to above
    auto &first = *s.begin();
    REQUIRE(first.i == -1);
    REQUIRE(first.c == 'a');
  }
}
} // namespace taintdag