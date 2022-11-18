/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#include <catch2/catch.hpp>

#include <sys/stat.h>

#include <array>
#include <cstdio>
#include <filesystem>
#include <tuple>

#include "taintdag/outputfile.h"
#include "taintdag/labels.h"
#include "taintdag/taint.h"

#include "utils.h"

namespace {

namespace td = taintdag;

td::source_offset_t rand_source_offset() {
  return td::test::rand_limit<td::source_offset_t>(td::max_source_offset);
}

td::source_index_t rand_source_index() {
  return td::test::rand_limit<td::source_index_t>(td::max_source_index);
}

struct RandomCount {
  td::label_t limit;
};

struct Count {
  td::label_t n;
};

std::tuple<td::label_t, td::taint_range_t>
rand_source_labels(td::Labels &labels, std::variant<Count, RandomCount> n) {
  auto nlabels =
      std::holds_alternative<Count>(n)
          ? std::get<Count>(n).n
          : td::test::rand_limit(std::get<RandomCount>(n).limit - 1) + 1;
  auto ofs = rand_source_offset();
  auto srcidx = rand_source_index();
  auto range = labels.create_source_labels(srcidx, ofs, nlabels);
  return {nlabels, range};
}

} // namespace

TEST_CASE("Serialize deserialize for different events") {
  INFO("Using seed: " << td::test::init_rand_seed());
  td::OutputFile<td::Labels> label_file{std::tmpnam(nullptr)};
  auto &labels{label_file.section<td::Labels>()};
  SECTION("Source ranges are of correct size and sound") {
    for (size_t i = 0; i < 16; i++) {
      auto [n, range] = rand_source_labels(labels, RandomCount{0xffff});
      // Labels are monotonically increasing
      REQUIRE(range.second > range.first);
      REQUIRE(n - 1 == (range.second - range.first));
    }
  }

  SECTION("Taints doesn't overlap") {
    std::vector<td::taint_range_t> ranges;
    for (size_t i = 0; i < 16; i++) {
      auto rsl{rand_source_labels(labels, RandomCount{0xffff})};
      auto range{std::get<td::taint_range_t>(rsl)};
      REQUIRE(std::all_of(ranges.begin(), ranges.end(), [range](auto &r) {
        return range.second <= r.first || range.first >= r.second;
      }));
      ranges.push_back(range);
    }
  }

  SECTION("Taint affects control flow") {
    auto rsl{rand_source_labels(labels, Count{4})};
    auto range{std::get<td::taint_range_t>(rsl)};
    SECTION("Default does not affect control flow") {
      for (auto lbl = range.first; lbl < range.second; lbl++) {
        auto st{std::get<td::SourceTaint>(labels.read_label(lbl))};
        REQUIRE(!st.affects_control_flow);
      }
    }

    SECTION("Source taint") {
      labels.affects_control_flow(range.first);
      auto st{std::get<td::SourceTaint>(labels.read_label(range.first))};
      REQUIRE(st.affects_control_flow);
    }

    SECTION("Union affects source labels as well") {
      auto ul = labels.union_taint(range.first, range.second - 1);
      labels.affects_control_flow(ul);

      auto u = std::get<td::UnionTaint>(labels.read_label(ul));
      REQUIRE(u.affects_control_flow);

      auto s1 = std::get<td::SourceTaint>(labels.read_label(u.lower));
      REQUIRE(s1.affects_control_flow);

      auto s2 = std::get<td::SourceTaint>(labels.read_label(u.higher));
      REQUIRE(s2.affects_control_flow);
    }

    SECTION("Range affects soruce labels") {
      auto rl = labels.union_taint(range.first, range.first + 1);
      auto rl2 = labels.union_taint(rl, range.first + 2);
      labels.affects_control_flow(rl2);

      auto r = std::get<td::RangeTaint>(labels.read_label(rl2));
      for (auto lbl = r.first; lbl <= r.last; lbl++) {
        REQUIRE(std::get<td::SourceTaint>(labels.read_label(lbl))
                    .affects_control_flow);
      }
    }
  }

  // Covered by the test cases in union.cpp, but this tests the full
  // union_taint method, not just the union-logic.
  SECTION("Union taints") {
    auto rsl{rand_source_labels(labels, Count{3})};
    auto range{std::get<td::taint_range_t>(rsl)};
    SECTION("Taint union of equal taints -> input taint") {
      auto ret = labels.union_taint(range.first, range.first);
      REQUIRE(ret == range.first);
    }

    SECTION("Taint union of non-equal taints -> new taint") {
      auto ret = labels.union_taint(range.first, range.first + 1);
      REQUIRE(ret >= range.second);
    }

    SECTION("Taint union (x,y), y -> (x,y)") {
      auto t2 = range.first + 1;
      auto t12 = labels.union_taint(range.first, t2);
      auto ret = labels.union_taint(t12, t2);
      REQUIRE(ret == t12);
    }

    SECTION("Taint union (x,y), x -> (x,y)") {
      auto t2 = range.first + 1;
      auto t12 = labels.union_taint(range.first, t2);
      auto ret = labels.union_taint(t12, range.first);
      REQUIRE(ret == t12);
    }

    SECTION("Taint union y, (x,y) -> (x,y)") {
      auto t2 = range.first + 1;
      auto t12 = labels.union_taint(range.first, t2);
      auto ret = labels.union_taint(t2, t12);
      REQUIRE(ret == t12);
    }

    SECTION("Taint union x, (x,y) -> (x,y)") {
      auto t2 = range.first + 1;
      auto t12 = labels.union_taint(range.first, t2);
      auto ret = labels.union_taint(range.first, t12);
      REQUIRE(ret == t12);
    }
  }

  SECTION("Capacity testing") {
    rand_source_labels(labels, Count{181202});
    for (size_t i = 181202; i < 850458; i++) {
      labels.union_taint(i - 3, i - 4);
    }
    REQUIRE(labels.count() == 850459);
  }

  SECTION("No recursive taint") {
    rand_source_labels(labels, RandomCount{32});

    for (auto iter = 0; iter < 10000; iter++) {
      auto max_label = labels.count() - 1;
      auto l1 = td::test::lbl_inrange(1, max_label);
      auto l2 = td::test::lbl_inrange(1, max_label);

      auto newlbl = labels.union_taint(l1, l2);
      CAPTURE(l1);
      CAPTURE(l2);
      CAPTURE(newlbl);

      auto t = labels.read_label(newlbl);
      if (auto *ut = std::get_if<td::UnionTaint>(&t)) {
        REQUIRE(newlbl != ut->lower);
        REQUIRE(newlbl != ut->higher);

        REQUIRE(ut->lower + 1 < ut->higher);
      }

      if (auto *rt = std::get_if<td::RangeTaint>(&t)) {
        CAPTURE(*rt);
        REQUIRE((rt->first > newlbl || rt->last < newlbl));
        REQUIRE(rt->first < rt->last);
      }
    }

    SECTION("Affects control flow backwards") {
      auto max_label = labels.count() - 1;
      for (auto lbl = max_label; lbl > 0; lbl--) {
        labels.affects_control_flow(lbl);
      }
    }

    SECTION("Affects control flow random") {
      auto max_label = labels.count() - 1;
      for (auto iter = max_label; iter > 0; iter--) {
        auto label = td::test::lbl_inrange(1, max_label);
        labels.affects_control_flow(label);
      }
    }
  }

  SECTION("Union of same labels twice in a row returns the previous label") {
    auto tr = std::get<td::taint_range_t>(rand_source_labels(labels, Count{5}));
    auto u1 = labels.union_taint(tr.first, tr.second - 1);
    auto u2 = labels.union_taint(tr.first, tr.second - 1);
    REQUIRE(u1 == u2);
  }

  SECTION("Range of same labels twice in a row returns the previous label") {
    auto tr = std::get<td::taint_range_t>(rand_source_labels(labels, Count{5}));
    auto u1 = labels.union_taint(tr.first, tr.first + 1);
    auto u2 = labels.union_taint(tr.first, tr.first + 1);
    REQUIRE(u1 == u2);
  }

  SECTION("Create duplicate label, but not same as last") {
    auto tr = std::get<td::taint_range_t>(rand_source_labels(labels, Count{5}));
    auto u01 = labels.union_taint(tr.first, tr.first + 1);
    labels.union_taint(tr.first, tr.first + 2);     // u02
    labels.union_taint(tr.first + 2, tr.first + 3); // u23
    auto u01_2 = labels.union_taint(tr.first, tr.first + 1);
    REQUIRE(u01 == u01_2);
  }
}