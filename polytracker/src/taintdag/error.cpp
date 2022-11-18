#include "taintdag/error.h"

#include <cstdlib>

namespace taintdag {

// Allows to control the effect of invoking error_exit. Primary purpose
// is to allow testing.
std::function<void(int)> error_function{&exit};
} // namespace taintdag
