
#ifndef POLYTRACKER_TAINTDAG_LABELDEQ_H
#define POLYTRACKER_TAINTDAG_LABELDEQ_H

#include <array>
#include <deque>
#include <variant>

#include "taintdag/taint.hpp"

namespace taintdag::utils {

// Starts out with N slots for labels on the stack and fall back to heap
// allocated deque if it grows larger.
template <size_t N> class LabelDeq {
  using deq_t = std::deque<label_t>;

public:
  // Undefined if empty()
  label_t pop_front() {
    struct V {
      label_t operator()(ArrayImpl &a) { return a.pop_front(); }
      label_t operator()(deq_t &d) {
        auto v = d.front();
        d.pop_front();
        return v;
      }
    };

    return std::visit(V{}, impl);
  }

  void push_back(label_t l) {
    struct V {
      bool operator()(ArrayImpl &a) {
        if (a.full())
          return false;
        a.push_back(val);
        return true;
      }
      bool operator()(deq_t &d) {
        d.push_back(val);
        return true;
      }
      label_t val;
    };

    if (!std::visit(V{l}, impl)) {
      migrate();
      push_back(l);
    }
  }

  bool empty() const {
    struct V {
      bool operator()(ArrayImpl const &a) const { return a.empty(); }
      bool operator()(deq_t const &d) const { return d.empty(); }
    };
    return std::visit(V{}, impl);
  }

private:
  void migrate() {
    deq_t d;
    auto &a = std::get<ArrayImpl>(impl);
    while (!a.empty())
      d.push_back(a.pop_front());

    impl = std::move(d);
  }

  struct ArrayImpl {
    std::array<label_t, N> arr_;
    size_t first{0};
    size_t last{0};

    size_t next(size_t i) const { return i % N; }

    bool empty() const { return first == last; }

    bool full() const { return (next(last) == first); }

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

  std::variant<ArrayImpl, deq_t> impl;
};
} // namespace taintdag::utils

#endif