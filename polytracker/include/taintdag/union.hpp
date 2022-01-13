#ifndef POLYTRACKER_TAINTDAG_UNION_H
#define POLYTRACKER_TAINTDAG_UNION_H

#include "taintdag/taint.hpp"

namespace taintdag {


  bool encloses(RangeTaint r, Taint const &other, label_t other_label) {
    return std::visit(struct A {

      bool operator()(RangeTaint o) const {
        return r.
      }

      bool operator()(UnionTaint o) const {

      }

      bool operator()(SourceTaint s) const {

      }

      A(label_t other)  : other_label{other}{}

      label_t other_label;
    }(other_label), 
    other);

  }


}
#endif