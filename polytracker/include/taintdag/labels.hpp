#ifndef TDAG_LABELS_HPP
#define TDAG_LABELS_HPP

#include "taintdag/section.hpp"
#include "taintdag/taint.hpp"
#include "taintdag/util.hpp"
#include "taintdag/encoding.hpp"
#include "taintdag/labeldeq.hpp"
#include "taintdag/union.hpp"

namespace taintdag {

struct Labels : public FixedSizeAlloc<storage_t> {
  static constexpr uint8_t tag{2};
  static constexpr size_t allocation_size{max_label + 1};

  // How many labels to scan backwards to detect if the same Taint is about to be
  // produced.
  static constexpr label_t redundant_label_range = 100;

  template <typename OF> Labels(SectionArg<OF> of) : FixedSizeAlloc{of.range} {
    util::dump_range("Labels", of.range);
    // Create the initial 'untainted' label. It will have label 0.
    construct(0u);
  }

  // Returns a range of source labels. The labels are guaranteed to be a
  // contiguous range. Each label is generated as referring to src, starting at
  // offset and then linearly to offset +length. The returned taint_range_t is
  // length labels in size.
  taint_range_t create_source_labels(source_index_t src, source_offset_t offset,
                                     size_t length) {
    auto maybe_range =
        construct_range(length, [src, &offset](uint8_t *p) mutable {
          new (p) storage_t{encode(SourceTaint{src, offset++})};
        });
    // TODO(hbrodin): Check valid return
    auto first = index(*maybe_range->begin());
    auto last = first + length - 1;
    return {first, last};
  }

  Taint read_label(label_t lbl) const {
    return decode(*std::next(begin(), lbl));
  }

  // Create a taint union
  label_t union_taint(label_t l, label_t r) {
    // TODO (hbrodin): Might already be covered by DFSAN
    if (l == r)
      return l;

    auto lval = read_label(l);
    auto rval = read_label(r);
    auto result = union_::compute(l, lval, r, rval);
    if (auto lbl = std::get_if<label_t>(&result))
      return *lbl;

    // At this point we should add a new taint, before doing so,
    // scan backwards to see if an identical taint was recently added
    auto encoded = encode(std::get<Taint>(result));

    auto hilbl = std::max(l, r);
    auto dup = duplicate_check(hilbl, encoded);
    if (dup)
      return dup.value();

    // Nothing left to check, just add the new taint.
    if (auto ret = construct(encoded); ret)
      return index(ret->t);

    error_exit("Failed to construct taint union.");
    return 0; // NOTE(hbrodin): Never reached due to error_exit that terminates.
  }

  // Returns a label_t for encoded if it exists within redundant_label_range
  // labels
  //
  // Scans backwards to locate an entry equal to encoded, disregarding any
  // affects control flow marker.
  // If one was found, the label is returned, else an empty optional.
  // hilbl is the highest label present in the encoded value and puts
  // a lower limit on how far back to scan. A union can only be created after
  // its highest label exists.
  std::optional<label_t> duplicate_check(label_t hilbl,
                                         storage_t encoded) const {

    auto b = std::make_reverse_iterator(end());
    auto e = std::make_reverse_iterator(begin() + hilbl);
    // Limit the scan to at most redundant_label_range, or available entries
    // if less than redundant_label_range
    if (std::distance(b, e) >= redundant_label_range) {
      e = b + redundant_label_range;
    }

    // Check if the encoded taint is already stored, if so reuse that label
    auto it = std::find_if(
        b, e, [encoded](storage_t s) { return equal_ignore_cf(s, encoded); });
    if (it != e) {
      return index(*it);
    }
    return {};
  }

  // Tags the label with 'affects control flow' and propagates to parent
  // hierarchy.
  //
  // As soon as a label affects control flow, any member of it's union or range
  // also affects control flow. Thus, mark all of them until a label that
  // affects control flow is encountered or a source taint is reached.
  void affects_control_flow(label_t label) {
    using labelq = utils::LabelDeq<32>;

    // Do a check on label to see if it shoudld be added to the q.
    // - If it affects control flow, ignore it. Already processed.
    // - If it is source taint, just mark it as affecting cf.
    // - else add for further processing
    auto add_to_q = [this](label_t label) -> bool {
      auto encoded = begin()[label];
      if (check_affects_control_flow(encoded))
        return false;

      if (is_source_taint(encoded)) {
        set_affects_control_flow(label);
        return false;
      }

      return true;
    };

    // Early out
    if (!add_to_q(label))
      return;

    labelq q;
    q.push_back(label);

    struct Visitor {
      void operator()(SourceTaint s) const {}

      void operator()(RangeTaint r) const {
        for (auto curr = r.first; curr <= r.last; curr++) {
          if (add_to_q(curr))
            q.push_back(curr);
        }
      }

      void operator()(UnionTaint u) const {
        if (add_to_q(u.lower))
          q.push_back(u.lower);
        if (add_to_q(u.higher))
          q.push_back(u.higher);
      }

      Visitor(labelq &q, decltype(add_to_q) f) : q{q}, add_to_q{f} {}

      labelq &q;
      decltype(add_to_q) add_to_q;
    };

    Visitor visitor{q, add_to_q};

    while (!q.empty()) {
      auto l = q.pop_front();
      auto encoded = begin()[l];

      set_affects_control_flow(l);
      std::visit(visitor, decode(encoded));
    }
  }

private:
  // TODO(hbrodin): This relies on the fact that we know that storage is aligned
  // uint64_t memory that can atomically be replaced. This implementation could
  // be modified to instead use a separate section of bits to mark it as
  // affecting control flow (using atomics). Or any other solution, that is more
  // correct.
  inline void set_affects_control_flow(label_t label) {
    auto p = begin() + label;
    *const_cast<storage_t *>(p) = add_affects_control_flow(*p);
  }
};
} // namespace taintdag

#endif