/*
 * Copyright (c) 2022-present, Trail of Bits, Inc.
 * All rights reserved.
 *
 * This source code is licensed in accordance with the terms specified in
 * the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include "taintdag/taint.h"

namespace taintdag::union_ {

using ReturnValue = std::variant<label_t, Taint>;

inline bool encloses(UnionTaint const &t, label_t l) {
  return t.higher == l || t.lower == l;
}

inline bool encloses(RangeTaint const &t, label_t l) {
  return t.first <= l && t.last >= l;
}

inline bool encloses(RangeTaint const &range, UnionTaint const &u) {
  return range.first <= u.lower && range.last >= u.higher;
}

// Is r a subrange of l?
inline bool encloses(RangeTaint const &super, RangeTaint const &sub) {
  return (super.first <= sub.first && super.last >= sub.last);
}

// The Visitor implementes the union of two labels.
// It either returns one of the labels, if either subsumes
// the other, or constructs a new Taint value representing
// the union of the two Taints.
// This class is intended to be used as a visitor for
// Taints:
// auto ret = std::visit(Visitor{l,r}, taintleft, taintright);
// Assumption: Equal labels and zero-lables (non-tainted) is already
// covered elsewhere.
class Visitor {
public:
  Visitor(label_t left, label_t right) : left_{left}, right_{right} {}

  ReturnValue operator()(SourceTaint const &l, SourceTaint const &r) const {
    if (l.index == r.index && l.offset == r.offset)
      return left_;

    return union_labels();
  }

  ReturnValue operator()(UnionTaint const &l, UnionTaint const &r) const {
    if (encloses(l, right_))
      return left_;
    if (encloses(r, left_))
      return right_;

    // Do the unions represent the same labels?
    // NOTE: No need to check for reverse since the labels are always stored
    // ordered.
    if (l.higher == r.higher && l.lower == r.lower)
      return left_;

      // Can the unions be converted to a range?
      /*
      if (l.lower < r.lower && l.higher < r.higher && (r.higher - l.lower) == 3)
          return RangeTaint{l.lower, r.higher};
      else if (r.lower < l.lower && r.higher < l.higher && (l.higher - r.lower)
      == 3) return RangeTaint{r.lower, l.higher};
          */
#if 0
      // Join the left union with right label -> range
      if (convert_to_range(l, right_))
        return RangeTaint{l.lower, l.higher};
      if (convert_to_range(r, left_))
        return RangeTaint{r.lower, r.higher};
#endif

    return union_labels();
  }

  ReturnValue operator()(RangeTaint const &l, RangeTaint const &r) const {
    if (encloses(l, right_))
      return left_;
    if (encloses(r, left_))
      return right_;

    if (encloses(l, r))
      return left_;
    if (encloses(r, l))
      return right_;

    // Are ranges adjacent? If so, create a larger range
    if (l.last + 1 == r.first)
      return RangeTaint{l.first, r.last};
    if (r.last + 1 == l.first)
      return RangeTaint{r.first, l.last};

    return union_labels();
  }

  ReturnValue operator()(SourceTaint const &l, UnionTaint const &r) const {
    return union_source(r, right_, left_);
  }

  ReturnValue operator()(SourceTaint const &l, RangeTaint const &r) const {
    return range_source(r, right_, left_);
  }

  ReturnValue operator()(UnionTaint const &l, SourceTaint const &r) const {
    return union_source(l, left_, right_);
  }

  ReturnValue operator()(UnionTaint const &l, RangeTaint const &r) const {
    return union_range(l, left_, r, right_);
  }

  ReturnValue operator()(RangeTaint const &l, SourceTaint const &r) const {
    return range_source(l, left_, right_);
  }

  ReturnValue operator()(RangeTaint const &l, UnionTaint const &r) const {
    return union_range(r, right_, l, left_);
  }

private:
#if 0
    // Can a union plus a label be converted to a range?
    // if union holds x, x+2 and the label is x+1, then yes.
    bool convert_to_range(UnionTaint const& u, label_t l) const {
      return u.higher - u.lower == 2 && u.lower + 1 == l;
    }
#endif

  ReturnValue range_source(RangeTaint const &r, label_t rlabel,
                           label_t sourcelabel) const {
    if (encloses(r, sourcelabel))
      return rlabel;

    // Source adjacent to range, just extend the range taint
    if (sourcelabel + 1 == r.first)
      return RangeTaint{sourcelabel, r.last};
    if (r.last + 1 == sourcelabel)
      return RangeTaint{r.first, sourcelabel};

    return union_labels();
  }

  ReturnValue union_source(UnionTaint const &u, label_t ulabel,
                           label_t sourcelabel) const {
    if (encloses(u, sourcelabel))
      return ulabel;

#if 0
      // Source label is exactly in between the union labels, convert to range
      if (convert_to_range(u, sourcelabel))
        return RangeTaint{u.lower, u.higher};
#endif

    return union_labels();
  }

  ReturnValue union_range(UnionTaint const &u, label_t ulabel,
                          RangeTaint const &r, label_t rlabel) const {
    if (encloses(r, ulabel))
      return rlabel;
    if (encloses(r, u))
      return rlabel;
    if (encloses(u, rlabel))
      return ulabel;

    if (u.lower + 1 == r.first) {
      if (encloses(r, u.higher))
        return RangeTaint(u.lower, r.last);
      if (u.higher == r.last + 1)
        return RangeTaint(u.lower, u.higher);
    } else if (u.higher == r.last + 1) {
      if (encloses(r, u.lower))
        return RangeTaint(r.first, u.higher);
    }

    // Union label adjacent to range?
    if (ulabel + 1 == r.first)
      return RangeTaint{ulabel, r.last};
    if (r.last + 1 == ulabel)
      return RangeTaint{r.first, ulabel};

#if 0
      // Range label between union elements?
      if (convert_to_range(u, rlabel))
        return RangeTaint{u.lower, u.higher};
#endif

    return union_labels();
  }

  // Creates a range or union depending on labels. If the labels
  // are adjacent a range is created, else a union is created.
  Taint union_labels() const {
    if (left_ + 1 == right_) {
      return RangeTaint{left_, right_};
    } else if (right_ + 1 == left_) {
      return RangeTaint{right_, left_};
    } else {
      return UnionTaint{left_, right_};
    }
  }

  label_t left_;
  label_t right_;
};

// Computes the union of two taint labels/values. There are two types of
// returns: 1a. right encloses left -> right label 1b. left encloses right ->
// left label
// 2. No direct overlap -> new taint value (RangeTaint if adjacent labels,
// UnionTaint if not)
inline ReturnValue compute(label_t left, Taint const &l, label_t right,
                           Taint const &r) {
  return std::visit(Visitor{left, right}, l, r);
}
} // namespace taintdag::union_