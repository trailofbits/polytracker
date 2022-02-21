#ifndef POLYTRACKER_TAINTDAG_ERROR_H
#define POLYTRACKER_TAINTDAG_ERROR_H

#include <cstdlib>

#include <iostream>

namespace taintdag {
template <typename... Msgs> void error_exit(Msgs &&...msgs) {
  std::cerr << "Fatal error. Abort.\n";
  (std::cerr << ... << msgs) << std::endl;
  exit(-1);
}
} // namespace taintdag

#endif