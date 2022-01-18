#include <catch2/catch.hpp>
#include <optional>

#include "taintdag/encoding.hpp"
#include "test_helpers.hpp"

using namespace taintdag;

TEST_CASE("Encoding decoding") {
  for (auto i=0;i<100000;i++) {
    auto [t,_] = test::rand_taint();
    auto encoded = taintdag::encode(t);
    Taint decoded = taintdag::decode(encoded);
    REQUIRE(decoded == t);
  }
}