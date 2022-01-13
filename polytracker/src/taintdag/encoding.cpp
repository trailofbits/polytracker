#include "taintdag/encoding.hpp"
#include "taintdag/error.hpp"

namespace taintdag {

// Encoding scheme:
// 64 bits in total
// [x y z*62]
// y is 1 if this Taint affects control flow, 0 if not
// Depending on the x (highest) bit interpretation of z is different
// For SourceTaint x is 1:
// [1 y o*54 i*8]
// Where o is source file offset and i is index of source file name (fdmapping idx)
// If x is 0:
// [0 y a*31 b*31]
// Depending on the value of a and b when interpreted as unsigned numbers the following
// scenarios exists:
// a>b the value is a UnionTaint having left: a and right: b.
// a<b the value is a RangeTaint having begin:a, end: b
// a==b invalid.
storage_t encode(Taint const &taint) {
  if (auto st = std::get_if<SourceTaint>(&taint)) {
    auto val = static_cast<storage_t>(1) << source_taint_bit_shift;
    val |= static_cast<storage_t>(st->affects_control_flow) << affects_control_flow_shift;
    val |= static_cast<storage_t>(st->offset & max_source_offset) << source_index_bits;
    val |= static_cast<storage_t>(st->index & source_index_mask);
    return val;
  } else if (std::holds_alternative<RangeTaint>(taint)) {
    // RangeTaint
    RangeTaint const& rt = std::get<RangeTaint>(taint);
    // rt.begin < rt.end always holds
    auto val = static_cast<storage_t>(0) << source_taint_bit_shift;
    val |= static_cast<storage_t>(rt.affects_control_flow) << affects_control_flow_shift;
    val |= rt.end;
    val |= (static_cast<storage_t>(rt.begin & label_mask) << val1_shift);
    return val;
  } else {
    // UnionTaint
    UnionTaint const& ut = std::get<UnionTaint>(taint);
    // ut.left > ut.right always holds
    auto val = static_cast<storage_t>(0) << source_taint_bit_shift;
    val |= static_cast<storage_t>(ut.affects_control_flow) << affects_control_flow_shift;
    val |= (static_cast<storage_t>(label_mask & ut.left) << val1_shift);
    val |= (ut.right & label_mask);
    return val;
  }
}

Taint decode(storage_t encoded) {
  bool affects_control_flow = (encoded >> affects_control_flow_shift) & 1;
  if ((encoded >> source_taint_bit_shift) & 1) {
    auto idx = encoded & source_index_mask;
    auto off = (encoded >> source_index_bits) & max_source_offset;
    return SourceTaint(idx, off, affects_control_flow);
  }

  label_t a = (encoded >> val1_shift) & label_mask;
  label_t b = encoded & label_mask;
  if (a == b)
    error_exit("Decoding invalid taint value, ", a, " == ", b, " encoded: ", encoded);

  if (a < b) {
    // RangeTaint
    return RangeTaint(a, b, affects_control_flow);
  } else {
    // UnionTaint
    return UnionTaint(a, b, affects_control_flow);
  }
}


bool is_source_taint(storage_t encoded) {
  return (encoded >> source_taint_bit_shift) & 1;
}

storage_t add_affects_control_flow(storage_t encoded) {
  return encoded | (static_cast<storage_t>(1) << affects_control_flow_shift);
}

}