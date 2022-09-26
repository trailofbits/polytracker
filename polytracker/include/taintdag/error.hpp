#ifndef POLYTRACKER_TAINTDAG_ERROR_H
#define POLYTRACKER_TAINTDAG_ERROR_H

#include <functional>
#include <iostream>

namespace taintdag {

extern std::function<void(int)> error_function;

template <typename... Msgs> void error_exit(Msgs &&...msgs) {
  std::cerr << "Fatal error. Abort.\n";
  (std::cerr << ... << msgs) << std::endl;
  error_function(-1);
}
} // namespace taintdag

#endif