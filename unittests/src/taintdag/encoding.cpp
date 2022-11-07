#include <catch2/catch.hpp>
#include <optional>

#include "taintdag/encoding.h"
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

TEST_CASE("Affects control flow") {
  auto [t, _] = test::rand_taint();
  auto encoded = encode(t);
  REQUIRE(!check_affects_control_flow(encoded));

  auto enc2 = add_affects_control_flow(encoded);
  REQUIRE(check_affects_control_flow(enc2));
}

TEST_CASE("Basic sanity checks") {
  for (size_t i=0;i<100000;i++) {
    auto [st, _] = test::random_source_taint();
    auto encoded = encode(st);
    REQUIRE((encoded >> source_taint_bit_shift));
    REQUIRE(is_source_taint(encoded));
    REQUIRE(check_affects_control_flow(encoded) == st.affects_control_flow);
  }
}


TEST_CASE("Compare equal ignore cf") {
  for (size_t i=0;i<1000;i++) {
    auto [t1, _1] = test::rand_taint();
    auto [t2, _2] = test::rand_taint();
    if (t1 == t2)
      continue;


    auto e1 = encode(t1);
    // Affects control flow
    auto e1cf = add_affects_control_flow(e1);
    REQUIRE(e1 != e1cf);

    auto e2 = encode(t2);

    REQUIRE(equal_ignore_cf(e1, e1));
    REQUIRE(equal_ignore_cf(e1, e1cf));
    REQUIRE(!equal_ignore_cf(e1, e2));
    REQUIRE(!equal_ignore_cf(e1cf, e2));

  }
}