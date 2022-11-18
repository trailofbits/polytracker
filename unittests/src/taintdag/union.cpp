#include <algorithm>
#include <iostream>
#include <numeric>
#include <string_view>
#include <vector>
#include <variant>


#include "taintdag/union.h"
#include "utils.h"

using namespace taintdag;

using label_set = std::vector<label_t>;
label_set to_labels(Taint const &t) {
  if (auto st = std::get_if<SourceTaint>(&t))
    return {};
  else if (auto ut = std::get_if<UnionTaint>(&t))
    return {ut->lower, ut->higher};
  
  label_set ls;
  auto rt = std::get<RangeTaint>(t);
  auto n = rt.last - rt.first + 1; 
  ls.resize(n);
  std::iota(ls.begin(), ls.end(), rt.first);
  return ls;
}

std::ostream& operator<<(std::ostream&os, label_set const& ls) {
  os << "[";
  for (auto v : ls)
    os << v << " ";
  os << "]";
  return os;
}

// NOTE: Include here to ensure operator<< is available to catch
#include <catch2/catch.hpp>

// Indication for max label, might be overrun in case of equal labels etc. (lower -> higher chance of reuse of labels)
label_t max_test_label = 32;
// Max source index to generate in SourceTaint (lower -> higher chance of reuse of labels)
label_t max_test_source_idx = 10;
// Max source offset to generate in SourceTaint (lower -> higher chance of reuse of labels)
label_t max_test_source_offset = 16;

// Number of test case iterations, higher takes longer but explores more paths/combinations
size_t const test_iterations = 30000;


// Create a random taint value/label pair
std::pair<Taint, label_t> rand_taint() {
  return test::rand_taint(max_test_label, max_test_source_idx, max_test_source_offset);
}

// Returns true if sub is included in super. Requires the ranges to be sorted
// according to <
bool includes(label_set super, label_set sub) {
  return std::includes(super.begin(), super.end(), sub.begin(), sub.end());
}


bool taint_included(label_set super, label_t sub_label, label_set sub) {
  return std::find(super.begin(), super.end(), sub_label) != super.end() ||
    includes(super, sub);
}

// TODO: Propagation of the affects_control_flow??

// Property based test verifying the implementation of the label union functionality
// Ensures that the effect of the union is the same as enumerating all labels and making an 
// explicit union of those.
TEST_CASE("Union Represents Same") {
  // To get variation in tests
  INFO("Seed value: " << test::init_rand_seed());
  unsigned nlabels = 0, nvalues = 0;
  for (auto iter=0;iter<test_iterations;iter++) {
    // Produce two random taint values
    auto [l, ll] = rand_taint();
    auto [r, lr] = rand_taint();

    // Ensure they represent different taint labels (precondition to compute below)
    if (lr == ll)
      lr++;

    // Compute the union
    union_::ReturnValue retval = union_::compute(ll, l, lr, r);

    label_set base_labels = {std::min(ll, lr), std::max(ll, lr)};
    auto labels_left = to_labels(l);
    auto labels_right = to_labels(r);

    // Dump troubleshooting info if test fails
    INFO("Left: {" << ll << " " << l << " " << labels_left << "}" );
    INFO("Right: {" << lr << " " << r << " " << labels_right << "}" );

    if (std::holds_alternative<label_t>(retval)) {
      // A label is returned, no new taint is constructed.
      // This implies that the taint at that label directly includes the other label, or
      // that the other label range is a subset of the return labels range.
      label_t lresult = std::get<label_t>(retval);
      INFO("Label result: " << lresult);
      REQUIRE((lresult == ll || lresult == lr));
      if (lresult == ll) {
        REQUIRE(taint_included(labels_left, lr, labels_right));
      } else {
        REQUIRE(taint_included(labels_right, ll, labels_left));
      }
      nlabels++;
    } else {
      // A new Taint value is constructed. It either represents a union of the base labels, or
      // it is a new union of the values represented by the base labels.
      auto labels_result = to_labels(std::get<Taint>(retval));
      INFO("Taint value result: " << labels_result);
      INFO("Base label union: " << base_labels);
      REQUIRE(taint_included(labels_result, ll, labels_left));
      REQUIRE(taint_included(labels_result, lr, labels_right));
      // TODO (hbrodin): Shoud probably check that labels_result does not contain any labels not in labels_left/right
      nvalues++;
    }
  }

  INFO("#labels " << nlabels << " #values " << nvalues);
}