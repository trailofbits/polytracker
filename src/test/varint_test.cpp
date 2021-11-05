#include "gigafunction/traceio/varint.h"
#include <catch2/catch.hpp>

using namespace gigafunction::varint;

TEMPLATE_TEST_CASE("Varint encoding, relevant types", "varint", uint64_t,
                   uint32_t, uint16_t, uint8_t) {
  srand(time(nullptr));
  auto seed = rand();
  INFO("Seed: " << seed);
  srand(seed);

  uint8_t buffer[max_storage<TestType>::value];
  auto beg = std::begin(buffer);
  auto end = std::end(buffer);
  SECTION("min/max value encoding") {
    auto i = GENERATE(std::numeric_limits<TestType>::min(),
                      std::numeric_limits<TestType>::max());
    TestType src{i}, dst;
    encode(beg, end, src);
    decode(beg, end, dst);
    REQUIRE(src == dst);
  }
  SECTION("encode larger type max value of decode type works") {
    uint64_t src = std::numeric_limits<TestType>::max();
    TestType dst;
    encode(beg, end, src);
    decode(beg, end, dst);
    REQUIRE(src == dst);
  }

  SECTION("Encode/decode random values") {

    TestType src = rand();
    for (size_t i = 0; i < 1000; i++) {
      TestType dst;
      encode(beg, end, src);
      decode(beg, end, dst);
      REQUIRE(src == dst);
      src *= rand();
    }
  }

  SECTION("Error cases") {
    SECTION("Encoding to small buffer") {
      TestType src = std::numeric_limits<TestType>::max();
      REQUIRE(!encode(beg, std::prev(end), src));
    }

    SECTION("Decoding using too short buffer") {
      TestType src = rand();
      for (size_t i = 0; i < 1000; i++) {
        auto ret = encode(beg, end, src);
        REQUIRE(ret);
        for (auto it = beg; it != ret.value(); it++) {
          TestType dst;
          REQUIRE(!decode(beg, it, dst));
        }
        src *= rand();
      }
    }

    SECTION("Decode overflow") {

      uint8_t b[max_storage<TestType>::value];
      // Will overflow all types

      std::fill(std::begin(b), std::end(b), 0xff);
      b[sizeof(b) - 1] &= 0x7f; // Signal end of encoded value

      TestType dst;
      REQUIRE(!decode(std::begin(b), std::end(b), dst));
    }
  }
}