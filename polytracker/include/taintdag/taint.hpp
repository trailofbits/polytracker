#ifndef POLYTRACKER_TAINTDAG_TAINT_H
#define POLYTRACKER_TAINTDAG_TAINT_H

#include <cassert>
#include <cstdint>
#include <iosfwd>
#include <limits>
#include <type_traits>
#include <variant>

namespace taintdag {

using label_t = uint32_t;
using storage_t = uint64_t;

static_assert(std::is_unsigned_v<storage_t>,
              "Assuming unsigned type for storage_t");
static_assert(std::is_unsigned_v<label_t>,
              "Assuming unsigned type for label_t");
static_assert(sizeof(storage_t) >= 2 * sizeof(label_t),
              "Invalid size relation between label_t and storage_t.");

const size_t storage_bits = std::numeric_limits<storage_t>::digits;
const size_t source_taint_bit_shift = storage_bits - 1;
const size_t affects_control_flow_shift = storage_bits - 2;

const storage_t mask_affects_control_flow =
    ~(static_cast<storage_t>(1) << affects_control_flow_shift);

// Using two bits to encode type info and affects control flowin the stored
// type. The stored type can hold at most two labels. Limit the label values to
// 1 bit less than original capacity, to accomodate the two type/control flow
// bits.
const size_t label_bits = std::numeric_limits<label_t>::digits - 1;
const label_t max_label = static_cast<label_t>(1 << label_bits) -
                          1; // This is safe, because of -1 above

const size_t val1_shift = label_bits;
const label_t label_mask = max_label;

// Use 8 bits for index into source vector
using source_index_t = uint8_t;
const size_t source_index_bits = std::numeric_limits<source_index_t>::digits;
const size_t max_source_index = std::numeric_limits<source_index_t>::max();
const source_index_t source_index_mask = max_source_index;

// Use the remaining bits for source file offset
const size_t source_offset_bits = storage_bits - source_index_bits - 2;
using source_offset_t = int64_t;
const source_offset_t max_source_offset =
    (static_cast<source_offset_t>(1) << source_offset_bits) - 1;

// NOTE (hbrodin): affects_control_flow is primarily a property of SourceTaint.
// It could be reflected by only using that bit in the SourceTaint type. An
// additional bit would then be available for RangeTaint and UnionTaint. I can't
// see any gain of doing so atm. The option exists if we want to use it. In that
// case, it would be required to traverse the taint structure to reach all
// SourceTaints to set the value. Now we can be lazy.
struct TaintBase {
  bool affects_control_flow;
  TaintBase(bool affects_control_flow)
      : affects_control_flow(affects_control_flow) {}
};

inline bool operator==(TaintBase const &l, TaintBase const &r) {
  return l.affects_control_flow == r.affects_control_flow;
}

struct SourceTaint : TaintBase {
  source_index_t index{0};
  source_offset_t offset{0};

  SourceTaint(source_index_t srcidx, source_offset_t srcoffset,
              bool affects_control_flow = false)
      : TaintBase(affects_control_flow), index{srcidx}, offset{srcoffset} {}
};

inline bool operator==(SourceTaint const &l, SourceTaint const &r) {
  return static_cast<TaintBase const &>(l) ==
             static_cast<TaintBase const &>(r) &&
         l.index == r.index && l.offset == r.offset;
}

// RangeTaint represents a range of labels, where is the last label + 1,
// much like iterator begin/end.
// TODO (hbrodin): Prevent ranges of single label.
// TODO (hbrodin): Consider if the range representation shall be inclusive? Do
// we need to represent empty ranges? isn't that an invalid state?

struct RangeTaint : TaintBase {
  RangeTaint(label_t argfirst, label_t arglast,
             bool affects_control_flow = false)
      : TaintBase(affects_control_flow), first{argfirst}, last{arglast} {
    assert((argfirst < arglast) &&
           "Expected first arg < last args when creating RangeTaint");
  }

  label_t first;
  label_t last; // first < last
};

inline bool operator==(RangeTaint const &l, RangeTaint const &r) {
  return static_cast<TaintBase const &>(l) ==
             static_cast<TaintBase const &>(r) &&
         l.first == r.first && l.last == r.last;
}

struct UnionTaint : TaintBase {
  // TODO (hbrodin): Prevent labels of equal value
  // TODO (hbrodin): Prevent labels of adjacent value (should prefer RangeTaint)
  UnionTaint(label_t label1, label_t label2, bool affects_control_flow = false)
      : TaintBase(affects_control_flow) {
    assert((label1 != label2) && "Expected non-equal labels in union");
    assert((label1 != label2 + 1) && "Expected non-adjacent labels");
    assert((label2 != label1 + 1) && "Expected non-adjacent labels");

    // Ensure left is the largest value
    if (label1 < label2) {
      lower = label1;
      higher = label2;
    } else {
      lower = label2;
      higher = label1;
    }
  }
  label_t lower;
  label_t higher;
};

inline bool operator==(UnionTaint const &l, UnionTaint const &r) {
  return static_cast<TaintBase const &>(l) ==
             static_cast<TaintBase const &>(r) &&
         l.lower == r.lower && l.higher == r.higher;
}

using Taint = std::variant<SourceTaint, RangeTaint, UnionTaint>;

// Represents first label_t, one past last label_t
// in spirit of begin()/end()
using taint_range_t = std::pair<label_t, label_t>;

std::ostream &operator<<(std::ostream &os, SourceTaint const &s);
std::ostream &operator<<(std::ostream &os, UnionTaint const &u);
std::ostream &operator<<(std::ostream &os, RangeTaint const &r);
std::ostream &operator<<(std::ostream &os, Taint const &t);

} // namespace taintdag
#endif