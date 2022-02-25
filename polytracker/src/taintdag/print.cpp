#include <iostream>

#include "taintdag/taint.hpp"

namespace taintdag {
std::ostream &operator<<(std::ostream &os, SourceTaint const &s) {
  os << "{SourceTaint, " << s.affects_control_flow << ", " << s.index << ", "
     << s.offset << "}";
  return os;
}

std::ostream &operator<<(std::ostream &os, UnionTaint const &u) {
  os << "{UnionTaint, " << u.affects_control_flow << ", " << u.higher << ", "
     << u.lower << "}";
  return os;
}

std::ostream &operator<<(std::ostream &os, RangeTaint const &r) {
  os << "{RangeTaint, " << r.affects_control_flow << ", " << r.first << ", "
     << r.last << "}";
  return os;
}

std::ostream &operator<<(std::ostream &os, Taint const &r) {
  if (std::holds_alternative<SourceTaint>(r))
    return os << std::get<SourceTaint>(r);
  if (std::holds_alternative<UnionTaint>(r))
    return os << std::get<UnionTaint>(r);
  if (std::holds_alternative<RangeTaint>(r))
    return os << std::get<RangeTaint>(r);
  return os;
}
} // namespace taintdag