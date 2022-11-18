#include <catch2/catch.hpp>

#include "taintdag/bitmap_section.h"

#include "utils.h"

namespace taintdag {

// Test various properties of the atomic bitmap and ensures it can be used with
// different bucket types (uint8_t, uint16_t, ...). NOTE: TestType is the name
// of the current type (named by Catch, the test-framework).
TEMPLATE_TEST_CASE("Atomic Bitmap", "atomicbitmap", uint8_t, uint16_t, uint32_t,
                   uint64_t) {
  static const BitCount capacity = 1024 * 1024;
  alignas(std::atomic<TestType>) uint8_t mem[capacity / 8] = {};

  using Section = BitmapSectionBase<22, capacity, TestType>;
  Section bs{mem};

  SECTION("Basic set/get operations") {

    REQUIRE(!bs.is_set(BitIndex{0}));
    REQUIRE(!bs.set(BitIndex{0}));
    REQUIRE(bs.is_set(BitIndex{0}));

    bs.set_range(BitIndex{1}, BitCount{212});

    for (BitIndex i = 0; i < BitIndex{213}; i++) {
      REQUIRE(bs.is_set(i));
    }
  }

  SECTION("Random set/get bits") {
    std::random_device rd;
    size_t seed = rd();
    size_t const iterations = 10000;

    std::uniform_int_distribution<BitIndex> uniform_dist(0, capacity - 1);
    std::mt19937 mt;

    // Set bits based on pseudo random sequence seeded with seed
    mt.seed(seed);
    for (size_t i = 0u; i < iterations; ++i) {
      bs.set(uniform_dist(mt));
    }

    // Ensure all bits previously set are set, by seeding the mt
    // with the same seed as previously
    mt.seed(seed);
    for (size_t i = 0u; i < iterations; ++i) {
      REQUIRE(bs.is_set(uniform_dist(mt)));
    }
  }

  auto check_not_set = [&bs](BitIndex first, BitCount count) {
    for (auto i = first; i < first + count; i++) {
      REQUIRE(!bs.is_set(i));
    }
  };

  auto check_is_set = [&bs](BitIndex first, BitCount count) {
    for (auto i = first; i < first + count; i++) {
      REQUIRE(bs.is_set(i));
    }
  };

  SECTION("Last bit before next bucket can be set") {
    BitIndex bi1 = sizeof(TestType) * 8 - 1;
    BitIndex bi2 = bi1 + sizeof(TestType) * 8;

    bs.set(bi1);
    bs.set(bi2);

    check_not_set(0, bi1);
    REQUIRE(bs.is_set(bi1));
    check_not_set(bi1 + 1, sizeof(TestType) * 8 - 1);
    REQUIRE(bs.is_set(bi2));
    check_not_set(bi2 + 1, sizeof(TestType) * 8);
  }

  SECTION("First bit in bucket can be set") {
    BitIndex bi1 = 0;
    BitIndex bi2 = bi1 + sizeof(TestType) * 8;

    bs.set(bi1);
    bs.set(bi2);

    REQUIRE(bs.is_set(bi1));
    check_not_set(bi1 + 1, sizeof(TestType) * 8 - 1);
    REQUIRE(bs.is_set(bi2));
    check_not_set(bi2 + 1, sizeof(TestType) * 8);
  }

  SECTION("Range end of bucket") {
    BitCount bc = 3;
    BitIndex bi = sizeof(TestType) * 8 - bc;
    bs.set_range(bi, bc);
    check_not_set(BitIndex(0), BitCount(bi));
    check_is_set(bi, bc);
    check_not_set(BitIndex(bi + bc), 128);
  }

  SECTION("Range beginning of bucket") {
    BitCount bc = 3;
    BitIndex bi = sizeof(TestType) * 8;
    bs.set_range(bi, bc);
    check_not_set(BitIndex(0), BitCount(bi));
    check_is_set(bi, bc);
    check_not_set(BitIndex(bi + bc), 128);
  }

  SECTION("Range overlapping bucket border") {
    BitCount bc = 2;
    BitIndex bi = sizeof(TestType) * 8 - bc + 1;
    bs.set_range(bi, bc);
    check_not_set(BitIndex(0), BitCount(bi));
    check_is_set(bi, bc);
    check_not_set(BitIndex(bi + bc), 128);
  }

  SECTION("Fill bucket in aligned range") {
    BitCount bc = sizeof(TestType) * 8;
    BitIndex bi = sizeof(TestType) * 8;
    bs.set_range(bi, bc);

    check_not_set(BitIndex(0), BitCount(bi));
    check_is_set(bi, bc);
    check_not_set(BitIndex(bi + bc), 128);
  }

  SECTION("Set range with overlap") {
    bs.set(BitIndex{99});

    bs.set_range(BitIndex{98}, BitCount{3});
    REQUIRE(bs.is_set(BitIndex{98}));
    REQUIRE(bs.is_set(BitIndex{99}));
    REQUIRE(bs.is_set(BitIndex{100}));

    bs.set(BitIndex{102});
    REQUIRE(bs.is_set(BitIndex{102}));
    REQUIRE(!bs.is_set(BitIndex{101}));

    bs.set_range(63, 130);
  }

  SECTION("Random single ranges set/get") {
    std::random_device rd;
    size_t seed = rd();
    CAPTURE(seed);

    std::mt19937 mt;

    std::uniform_int_distribution<BitIndex> start_dist(0, capacity - 1);
    for (size_t i = 0; i < 32; i++) {
      auto start = start_dist(mt);
      CAPTURE(start);

      std::uniform_int_distribution<BitCount> len_dist(0, capacity - start);
      auto len = len_dist(mt);
      CAPTURE(len);

      bs.set_range(start, len);
      check_not_set(0, start);
      check_is_set(start, len);
      auto end = BitIndex{start + len};
      check_not_set(end, capacity - end);

      // We cheat by clearing the backing store under the feet of
      // BitmapSectionBase
      std::fill(std::begin(mem), std::end(mem), 0);
    }
  }

  SECTION("Size increase") {
    REQUIRE(bs.size() == 0);

    // First bit set, requires some size
    bs.set(1);
    REQUIRE(bs.size() == sizeof(TestType));

    // Last bit within same bucket, now change in size
    bs.set(sizeof(TestType) * 8 - 1);
    REQUIRE(bs.size() == sizeof(TestType));

    // First bit in next bucket, size increases again
    bs.set(sizeof(TestType) * 8);
    REQUIRE(bs.size() == sizeof(TestType) * 2);
  }

  SECTION("Error cases with out of bounds access") {
    test::ErrorExitReplace errthrow;

    REQUIRE_THROWS_AS(bs.is_set(capacity), test::ErrorExit);
    REQUIRE_THROWS_AS(bs.set(capacity), test::ErrorExit);
    REQUIRE_THROWS_AS(bs.set_range(capacity - 2, 3), test::ErrorExit);
  }
}
} // namespace taintdag