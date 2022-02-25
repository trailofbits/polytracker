
#ifndef POLYTRACKER_TAINTDAG_LABELDEQ_H
#define POLYTRACKER_TAINTDAG_LABELDEQ_H

#include <deque>

#include "taintdag/taint.hpp"

namespace taintdag::utils {

// Starts out with N slots for labels on the stack and fall back to heap
// allocated deque if it grows larger.
template <size_t N> class LabelDeq {
  using deq_t = std::deque<label_t>;

public:
  LabelDeq() {
    new (&storage_) ArrayImpl;
    arr_active = true;
  }
  // NOTE (hbrodin): Not implementing copy/move construct/assign  right now
  // because it is not needed. Should be easy to fix though.
  LabelDeq(LabelDeq const &) = delete;
  LabelDeq(LabelDeq &&) = delete;

  LabelDeq &operator=(LabelDeq const &) = delete;
  LabelDeq &operator=(LabelDeq &&) = delete;

  ~LabelDeq() {
    if (arr_active)
      as_arr().~ArrayImpl();
    else
      as_deq().~deq_t();
  }

  // Undefined if empty()
  label_t pop_front() {
    if (arr_active) {
      return as_arr().pop_front();
    } else {
      auto &d = as_deq();
      auto v = d.front();
      d.pop_front();
      return v;
    }
  }

  void push_back(label_t l) {
    if (arr_active) {
      if (as_arr().full()) {
        migrate(l);
      } else {
        as_arr().push_back(l);
      }
    } else {
      as_deq().push_back(l);
    }
  }

  bool empty() const {
    if (arr_active) {
      return as_arr().empty();
    } else {
      return as_deq().empty();
    }
  }

private:
  void migrate(label_t l) {
    deq_t d;
    auto &a = as_arr();
    while (!a.empty())
      d.push_back(a.pop_front());

    d.push_back(l);

    as_arr().~ArrayImpl();
    new (&storage_) deq_t(std::move(d));
    arr_active = false;
  }

  struct ArrayImpl {
    label_t arr_[N];
    size_t first{0};
    size_t last{0};

    size_t next(size_t i) const { return (i + 1) % N; }

    bool empty() const { return first == last; }

    bool full() const { return (last == next(first)); }

    label_t pop_front() {
      auto v = arr_[last];
      last = next(last);
      return v;
    }

    void push_back(label_t l) {
      arr_[first] = l;
      first = next(first);
    }
  };

  inline deq_t &as_deq() { return *reinterpret_cast<deq_t *>(&storage_); }

  inline deq_t const &as_deq() const {
    return *reinterpret_cast<deq_t const *>(&storage_);
  }

  inline ArrayImpl &as_arr() {
    return *reinterpret_cast<ArrayImpl *>(&storage_);
  }

  inline ArrayImpl const &as_arr() const {
    return *reinterpret_cast<ArrayImpl const *>(&storage_);
  }
  // Is the array implementation active?
  bool arr_active;

  using au = std::aligned_union_t<0, ArrayImpl, deq_t>;
  au storage_;
};
} // namespace taintdag::utils

#endif