#include <array>
#include <filesystem>
#include <catch2/catch.hpp>

#include "taintdag/fdmapping.hpp"
#include "taintdag/taintdag.hpp"
#include "test_helpers.hpp"

using namespace taintdag;


struct mem {
  char *begin {nullptr};
  char *end{nullptr};
  size_t size;

  mem(size_t num_slots = max_label) :size{num_slots*sizeof(storage_t)} {
    auto m = mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (m == MAP_FAILED)
      throw std::runtime_error("Failed to map memory");
    begin = reinterpret_cast<char*>(m);
    end = begin + size;
  }

  ~mem() {
    if (begin)
      munmap(begin, size);
  }
};

namespace {
  source_offset_t rand_source_offset() {
    return test::rand_limit<source_offset_t>(max_source_offset);
  }

  source_index_t rand_source_index() {
    return test::rand_limit<source_index_t>(max_source_index);
  }


  struct RandomCount {
    label_t limit;
  };

  struct Count {
    label_t n;
  };

  // Construct random source labels
  // The tuple contains:
  // number of labels requested
  // source offset
  // source index
  // Returned taint_range_t
  std::tuple<label_t, source_offset_t, source_index_t, taint_range_t> rand_source_labels(TaintDAG &td, std::variant<Count, RandomCount> n) {
      auto nlabels= std::holds_alternative<Count>(n) ? std::get<Count>(n).n : test::rand_limit(std::get<RandomCount>(n).limit-1)+1;
      auto ofs = rand_source_offset();
      auto srcidx = rand_source_index();
      auto range = td.create_source_labels(srcidx, ofs, nlabels);
      return {nlabels, ofs, srcidx, range};
  }
}

TEST_CASE("Serialize deserialize for different events") {
  srand(time(nullptr));
  auto seed = rand();
  INFO("Using seed: " << seed);
  srand(seed);

  mem m; 
  TaintDAG td{m.begin, m.end};


  SECTION("Source ranges are of correct size and sound") {
    for (size_t i=0;i<16;i++) {
      auto [n, _1, _2, range] = rand_source_labels(td, RandomCount{0xffff});

      // Labels are monotonically increasing
      REQUIRE(range.second > range.first);
      REQUIRE(n == (range.second - range.first));
    }
  }

  SECTION("Taints doesn't overlap") {
    std::vector<taint_range_t> ranges;
    for (size_t i=0;i<16;i++) {
      auto [n, ofs, srcidx, tr_] = rand_source_labels(td, RandomCount{0xffff});
      taint_range_t tr = tr_; // For some reason the lambda capture doesn't work with tr_???

      REQUIRE(std::all_of(ranges.begin(), ranges.end(), [tr](auto &r) {
        // We know from above that tr.last >= tr.first
        return tr.second <= r.first || tr.first >= r.second;
      }));

      ranges.push_back(tr);
    }
  }
  SECTION("Taint affects control flow") {
    auto [_1, _2, _3, tr] = rand_source_labels(td, Count{3});

    SECTION("Default does not affect control flow") {
      for (auto lbl = tr.first;lbl<tr.second;lbl++) {
        auto st = std::get<SourceTaint>(td.read_label(lbl));
        REQUIRE(!st.affects_control_flow);
      }
    }

    SECTION("Source taint") {
      td.affects_control_flow(tr.first);

      auto st = std::get<SourceTaint>(td.read_label(tr.first));
      REQUIRE(st.affects_control_flow);
    }

    SECTION("Union affects source labels as well") {
      auto ul = td.union_taint(tr.first, tr.second-1);
      td.affects_control_flow(ul);

      auto u = std::get<UnionTaint>(td.read_label(ul));
      REQUIRE(u.affects_control_flow);

      auto s1 = std::get<SourceTaint>(td.read_label(u.lower));
      REQUIRE(s1.affects_control_flow);

      auto s2 = std::get<SourceTaint>(td.read_label(u.higher));
      REQUIRE(s2.affects_control_flow);
    }

    SECTION("Range affects soruce labels") {
      auto rl = td.union_taint(tr.first, tr.first +1);
      auto rl2 = td.union_taint(rl, tr.first+2);
      td.affects_control_flow(rl2);

      auto r = std::get<RangeTaint>(td.read_label(rl2));
      for (auto lbl = r.first;lbl<=r.last;lbl++) {
        REQUIRE(std::get<SourceTaint>(td.read_label(lbl)).affects_control_flow);
      }
    }

  }

  // Covered by the test cases in union.cpp, but this tests the full
  // union_taint method, not just the union-logic.
  SECTION("Union taints") {
    auto tr = std::get<taint_range_t>(rand_source_labels(td, Count{3}));


    SECTION("Taint union of equal taints -> input taint") {
      auto ret = td.union_taint(tr.first, tr.first);
      REQUIRE(ret == tr.first);
    }

    SECTION("Taint union of non-equal taints -> new taint") {
      auto ret = td.union_taint(tr.first, tr.first+1);
      REQUIRE(ret >= tr.second);
    }

    SECTION("Taint union (x,y), y -> (x,y)") {
      auto t2 = tr.first + 1;
      auto t12 = td.union_taint(tr.first, t2);
      auto ret = td.union_taint(t12, t2);
      REQUIRE(ret == t12);
    }

    SECTION("Taint union (x,y), x -> (x,y)") {
      auto t2 = tr.first + 1;
      auto t12 = td.union_taint(tr.first, t2);
      auto ret = td.union_taint(t12, tr.first);
      REQUIRE(ret == t12);
    }

    SECTION("Taint union y, (x,y) -> (x,y)") {
      auto t2 = tr.first + 1;
      auto t12 = td.union_taint(tr.first, t2);
      auto ret = td.union_taint(t2, t12);
      REQUIRE(ret == t12);
    }

    SECTION("Taint union x, (x,y) -> (x,y)") {
      auto t2 = tr.first + 1;
      auto t12 = td.union_taint(tr.first, t2);
      auto ret = td.union_taint(tr.first, t12);
      REQUIRE(ret == t12);
    }
  }


  SECTION("Taint iteration") {
    auto tr = std::get<taint_range_t>(rand_source_labels(td, Count{3}));
    auto t1 = tr.first;
    auto t2 = tr.first + 1;
    auto t3 = tr.first + 2;

    SECTION("Iterator have correct value_type") {
      REQUIRE(std::is_same_v<label_t, TaintDAG::taint_iterator::value_type>);
      REQUIRE(std::is_same_v<std::iterator_traits<taintdag::TaintDAG::taint_iterator>::value_type,
        taintdag::TaintDAG::taint_iterator::value_type>);
    }

    SECTION("Source taint iteration is empty iteration") {
      auto [it,end] = td.iter_taints(t1);
      REQUIRE(it == end);
    }

    SECTION("Depth first iteration") {
      auto t12 = td.union_taint(t1, t2);
      auto t23 = td.union_taint(t2, t3);
      auto t1223 = td.union_taint(t12, t23);

      auto [it, end] = td.iter_taints(t1223);
      // Depth First Search
      auto order = std::array<label_t, 6>{t12, t1, t2, t23, t2, t3};
      for (auto oit = order.begin();it!=end;++it, ++oit) {
        REQUIRE(*it == *oit);
      }
    }
  }

  SECTION("Capacity testing") {
    rand_source_labels(td, Count{181202});

    for (size_t i=181202;i<850458;i++) {
      td.union_taint(i-3, i-4);
    }
    REQUIRE(td.label_count() == 850459);
  }


  SECTION("No recursive taint") {
    auto [n, ofs, srcidx, tr_] = rand_source_labels(td, RandomCount{32});

    for (auto iter =0;iter<10000;iter++) {
      auto max_label = td.label_count() -1;
      auto l1 = test::lbl_inrange(1, max_label);
      auto l2 = test::lbl_inrange(1, max_label);

      auto newlbl = td.union_taint(l1, l2);
      CAPTURE(l1);
      CAPTURE(l2);
      CAPTURE(newlbl);

      auto t = td.read_label(newlbl);
      if (auto *ut = std::get_if<UnionTaint>(&t)) {
        REQUIRE(newlbl != ut->lower);
        REQUIRE(newlbl != ut->higher);
      }

      if (auto *rt = std::get_if<RangeTaint>(&t)) {
        CAPTURE(*rt);
        REQUIRE((rt->first > newlbl || rt->last < newlbl));
      }
    }

    SECTION("Affects control flow backwards") {
      auto max_label = td.label_count() -1;
      for (auto lbl = max_label;lbl>0;lbl--) {
        td.affects_control_flow(lbl);
      }
    }

    SECTION("Affects control flow random") {
      auto max_label = td.label_count() -1;
      for (auto iter = max_label;iter>0;iter--) {
        auto label = test::lbl_inrange(1, max_label);
        td.affects_control_flow(label);
      }
    }
  }
}