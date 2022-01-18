#include <catch2/catch.hpp>
#include <optional>

#include "taintdag/encoding.hpp"
#include "test_helpers.hpp"

using namespace taintdag;

TEST_CASE("Encoding decoding") {
  std::optional<Taint> t;
  for (auto i=0;i<100000;i++) {
    auto choice = test::rand_limit(3u);
    INFO("Choice is " << choice);
    bool affects_control_flow = test::rand_limit(2u);
    source_offset_t ofs = test::rand_limit(max_source_offset+1u);
    source_index_t idx = test::rand_limit(max_source_index+1u);
    label_t label1 = test::rand_limit(max_label + 1u);
    label_t label2 = test::rand_limit(max_label + 1u);
    INFO("Offset: " << ofs << " idx " << static_cast<unsigned>(idx) << " label1 " << label1 << " label2 " << label2);
    if (label2 == label1)
      continue; // Not valid
    switch (choice)
    {
    case 0:
      t = SourceTaint{idx, ofs, affects_control_flow};
      break;
    case 1:
      t = RangeTaint{std::min(label1, label2), std::max(label1, label2)};
      break;
    case 2:
      t = UnionTaint{label1, label2};
      break;
    }
    auto encoded = taintdag::encode(*t);
    Taint decoded = taintdag::decode(encoded);
    REQUIRE(decoded.index() == choice);
    if (!(decoded == t)) {
      INFO("Decoding differs"); // Easy breakpoint
    }
    REQUIRE(decoded == t);
  }
}