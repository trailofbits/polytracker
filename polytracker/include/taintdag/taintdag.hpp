#ifndef POLYTRACKER_TAINTDAG_TAINTDAG_H
#define POLYTRACKER_TAINTDAG_TAINTDAG_H
#include <atomic>
#include <cassert>
#include <limits>
#include <numeric>
#include <optional>
#include <type_traits>
#include <vector>
#include <deque>

#include <sys/mman.h>

#include "taintdag/encoding.hpp"
#include "taintdag/fdmapping.hpp"
#include "taintdag/taint.hpp"
#include "taintdag/union.hpp"

namespace taintdag {

class TaintDAG {
public:

  class taint_iterator;
  using iterator = taint_iterator;

  TaintDAG(char *begin, char *end)
   : p_{reinterpret_cast<storage_t*>(begin)}, storage_size_{static_cast<size_t>(end-begin)} {
    if (end < begin)
      error_exit("TaintDAG: end < begin");
    if (storage_size_ < max_label * sizeof(storage_t))
      error_exit("Insufficient storage size for ", max_label, " labels.");
  }

  TaintDAG(TaintDAG const&) = delete;
  TaintDAG(TaintDAG&&) = delete;
  TaintDAG &operator=(TaintDAG const&) = delete;
  TaintDAG &operator=(TaintDAG &&o) = delete;


  // Get the current number of labels
  size_t label_count() const {
    return current_idx_.load(std::memory_order_relaxed);
  }

  taint_range_t reserve_source_labels(label_t length) {
    auto lbl = increment(length);
    return {lbl, lbl+length};
  }

  void assign_source_labels(taint_range_t range, source_index_t source_idx, source_offset_t offset) {
    std::generate(&p_[range.first], &p_[range.second], [source_idx, source_offset = offset]() mutable {
      return encode(SourceTaint(source_idx, source_offset++));
    });
  }

  // creates labels corresponding to a read of 'length' from 'source_fd' at 'offset'
  taint_range_t create_source_labels(source_index_t source_idx, source_offset_t offset, label_t length) {
    assert(offset < max_source_offset && "Source offset exceed limits for encoding");
    auto range = reserve_source_labels(length);
    assign_source_labels(range, source_idx, offset);
    return range;
  }

  Taint read_label(label_t lbl) {
    // TODO (hbrodin): Should include range check...
    return decode(p_[lbl]);
  }

  void affects_control_flow(label_t label) {
    using labelq = std::deque<label_t>;

    // Early out
    if (check_affects_control_flow(p_[label]))
      return;

    labelq q;
    q.push_back(label);

    struct Visitor {
      void operator()(SourceTaint s) { }

      void operator()(RangeTaint r) {
        for (auto curr = r.first;curr <= r.last;curr++) {
          q.push_back(curr);
        }
      }

      void operator()(UnionTaint u) {
        q.push_back(u.lower);
        q.push_back(u.higher);
      }

      Visitor(labelq &q) : q{q} {
      }
      labelq &q;
    };


    while (!q.empty()) {
      auto l = q.front();
      q.pop_front();

      auto encoded = p_[l];

      // Early out
      if (check_affects_control_flow(encoded))
        continue;

      auto encoded_waffects = add_affects_control_flow(encoded);
      p_[l] = encoded_waffects;
      if (!is_source_taint(encoded_waffects)) {
        std::visit(Visitor{q}, decode(encoded_waffects));
      }
    }
  }

  // Create a taint union
  label_t union_taint(label_t l, label_t r) {
    // TODO (hbrodin): Might already be covered by DFSAN
    if (l == r)
      return l;

    // Simple check, did we just create this union? If so, reuse it
    // TODO (hbrodin): Extend the check to a range backwards...
    auto prevlbl = label_count()-1; // Safe, since we start at 1.
    auto prev = decode(p_[prevlbl]);
    if (auto ut = std::get_if<UnionTaint>(&prev)) {
      if (ut->lower == r && ut->higher == l)
        return prevlbl;
      if (ut->lower == l && ut->higher == r)
        return prevlbl;
    } else if (auto rt = std::get_if<RangeTaint>(&prev)) {
      if (rt->first == l && rt->last == r)
        return prevlbl;
      if (rt->first == r && rt->last == l)
        return prevlbl;
    }


    auto lval = decode(p_[l]);
    auto rval = decode(p_[r]);
    auto result = union_::compute(l, lval, r, rval);
    if (auto lbl = std::get_if<label_t>(&result))
      return *lbl;
    auto idx = increment(1);
    p_[idx] = encode(std::get<Taint>(result));
    return idx;
  }


  // Iterate through the entire taint hierarchy for a certain taint
  class taint_iterator {
    public:

    using value_type = label_t;
    using difference_type = label_t;
    using pointer = value_type*;
    using reference = value_type&;
    using iterator_category = std::forward_iterator_tag;

    taint_iterator(label_t start, TaintDAG const &td) :td{td} {
      stack.push_back(start);
      ++*this;
    }

    // Construct end iterator
    taint_iterator(TaintDAG const&td) : td{td} {
    }

    reference operator*() {
      return stack.back();
    }

    taint_iterator &operator++() {
      auto v = stack.back();
      stack.pop_back();

      Taint t = decode(td.p_[v]);
      if (std::holds_alternative<UnionTaint>(t)) {
        UnionTaint const& ut = std::get<UnionTaint>(t);
        stack.push_back(ut.lower);
        stack.push_back(ut.higher);
      }

      return *this;
    }

    bool operator==(taint_iterator const& other) const {
      return &td == &other.td && stack == other.stack;
    }

    bool operator!=(taint_iterator const &other) const {
      return !(*this == other);
    }

  private:
    std::vector<label_t> stack;
    TaintDAG const& td;
  };

  // Iterate through all taint sources for a certain taint
  class taint_source_iterator {

  };


  std::pair<taint_iterator, taint_iterator> iter_taints(label_t start) {
    return {taint_iterator{start, *this}, taint_iterator{*this}};
  }

private:


  label_t increment(label_t length) {
    label_t next;
    auto old = current_idx_.load(std::memory_order_relaxed);
    do {
      next = old+length;
      if (next < old) {
        assert(false && "Overflow detected, out of taint labels");
      }
    } while (!current_idx_.compare_exchange_weak(old, next, std::memory_order_relaxed));
    return old;
  }


  storage_t *p_{nullptr};
  size_t storage_size_{0};
  // Starts at 1, zero is 'untainted'
  std::atomic<label_t> current_idx_{1};
};

}
#endif