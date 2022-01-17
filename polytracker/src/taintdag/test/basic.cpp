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

TEST_CASE("Serialize deserialize for different events") {
  srand(time(nullptr));
  auto seed = rand();
  INFO("Using seed: " << seed);
  srand(seed);

  mem m; 
  TaintDAG td{m.begin, m.end};


  SECTION("Source ranges are of correct size and sound") {
    for (size_t i=0;i<16;i++) {
      auto n= rand_limit(0xffffu);

      source_offset_t ofs = rand_limit(max_source_offset);
      source_index_t srcidx = rand_limit(max_source_index+1);
      auto range = td.create_source_labels(srcidx, ofs, n);

      // Labels are monotonically increasing
      REQUIRE(range.second > range.first);
      REQUIRE(n == (range.second - range.first));
    }
  }

  SECTION("Taints doesn't overlap") {
    std::vector<taint_range_t> ranges;
    for (size_t i=0;i<16;i++) {
      auto n= rand_limit(0xffffu);

      source_offset_t ofs = rand_limit(max_source_offset);
      source_index_t idx = rand_limit(max_source_index+1);
      auto tr = td.create_source_labels(idx, ofs, n);

      REQUIRE(std::all_of(ranges.begin(), ranges.end(), [tr](auto &r) {
        // We know from above that tr.last >= tr.first
        return tr.second <= r.first || tr.first >= r.second;
      }));

      ranges.push_back(tr);
    }
  }
  SECTION("Taint affects control flow") {
    source_offset_t ofs = rand_limit(max_source_offset);
    source_index_t idx = rand_limit(max_source_index+1);
    auto tr = td.create_source_labels(idx, ofs, 3);

    td.affects_control_flow(tr.first);
  }

  SECTION("Union taints") {
    source_offset_t ofs = rand_limit(max_source_offset);
    source_index_t idx = rand_limit(max_source_index+1);
    auto tr = td.create_source_labels(idx, ofs, 3);


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
    source_offset_t ofs = rand_limit(max_source_offset);
    source_index_t idx = rand_limit(max_source_index+1);
    auto tr = td.create_source_labels(idx, ofs, 3);
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
    source_offset_t ofs = rand_limit(max_source_offset);
    source_index_t idx = rand_limit(max_source_index+1);
    td.create_source_labels(idx, ofs, 181202);

    for (size_t i=181202;i<850458;i++) {
      td.union_taint(i-3, i-4);
    }
    REQUIRE(td.label_count() == 850459);
  }
}