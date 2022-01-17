#ifndef POLYTRACKER_TAINTDAG_TAINTDAG_H
#define POLYTRACKER_TAINTDAG_TAINTDAG_H
#include <atomic>
#include <cassert>
#include <limits>
#include <numeric>
#include <optional>
#include <type_traits>
#include <vector>

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


  // creates labels corresponding to a read of 'length' from 'source_fd' at 'offset'
  taint_range_t create_source_labels(source_index_t source_idx, source_offset_t offset, label_t length) {
    assert(offset < max_source_offset && "Source offset exceed limits for encoding");

    auto lbl = increment(length);
    std::generate_n(&p_[lbl], length, [source_idx, source_offset = offset]() mutable {
      return encode(SourceTaint(source_idx, source_offset++));
    });
    return {lbl, lbl + length};
  }

  // NOTE (hbrodin): Ideally, this should flow to all ancestor labels and ultimately sourcetaints
  void affects_control_flow(label_t label) {
    p_[label] = add_affects_control_flow(p_[label]);
  }

  // Create a taint union
  label_t union_taint(label_t l, label_t r) {
    if (l == r)
      return l;

    auto lval = decode(p_[l]);
    auto rval = decode(p_[r]);
    auto result = union_::compute(l, lval, r, rval);
    if (std::holds_alternative<label_t>(result))
      return std::get<label_t>(result);
    auto idx = increment(1);
    p_[idx] = encode(std::get<Taint>(result));
    return idx;

#if 0
    auto lval = decode(p_[l]);
    if (UnionTaint *ut = std::get_if<UnionTaint>(&lval)) {
      if (ut->left == r || ut->right == r)
        return l;
    }

    auto rval = decode(p_[r]);
    if (UnionTaint *ut = std::get_if<UnionTaint>(&rval)) {
      if (ut->left == l || ut->right == l)
        return r;
    }

    // TODO (hbrodin): Just aiming for something working, later make more sophisticated choices.
    auto idx = increment(1);
    UnionTaint ut{l, r};
    p_[idx] = encode(ut);
    return idx;
    #endif
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