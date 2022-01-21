#include <catch2/catch.hpp>
#include <list>

#include "taintdag/labeldeq.hpp"
#include "test_helpers.hpp"

using namespace taintdag;

TEST_CASE("LabelDeq behaves equal to std list (push_back/pop_front)") {
  auto s = test::init_rand_seed();
  INFO("Init rand with seed" << s)

  for (auto i=0;i<10000;i++) {
    utils::LabelDeq<16> ld;
    std::list<label_t> compare;

    auto nops = test::rand_limit(128u);
    for (auto j=0;j<nops;j++) {
      REQUIRE(ld.empty() == compare.empty());

      // Slightly higher chance of pushing than popping
      if ((test::rand_limit(100u) < 51)) {
        label_t l = test::lbl_inrange();
        INFO("Push " << l);
        ld.push_back(l);
        compare.push_back(l);
      } else {
        if (compare.empty()) {
          INFO("Hit empty");
          continue;
        }
        INFO("Pop ");
        label_t l1 = ld.pop_front();
        label_t l2 = compare.front();
        compare.pop_front();
        CAPTURE(l1);
        CAPTURE(l2);

        REQUIRE(l1 == l2);
      }
    }

    // Pop rest and check
    while (!ld.empty()) {
        label_t l1 = ld.pop_front();
        label_t l2 = compare.front();
        compare.pop_front();
        CAPTURE(l1);
        CAPTURE(l2);
    }
    REQUIRE(compare.empty());

  }
  



}