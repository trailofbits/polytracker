#include <string>

#include "polytracker/early_construct.h"
#include "polytracker/polytracker.h"
#include "taintdag/polytracker.h"

EARLY_CONSTRUCT_EXTERN_GETTER(taintdag::PolyTracker, polytracker_tdag);

namespace polytracker {

void taint_argv(int argc, char *argv[]) {

  // The check could be done in the calling code, for performance reasons.
  // However this function should only ever be invoked once (from main).
  if (!polytracker_taint_argv)
    return;

  if (argc <= 0) {
    // Weird. Not much to do though.
    return;
  }

  auto &polyt = get_polytracker_tdag();

  for (int i = 0; i < argc; ++i) {
    auto name = std::string{"argv["} + std::to_string(i) + "]";
    // NOTE(hbrodin): Currently not tainting terminating null char.
    polyt.create_taint_source(
        name, {reinterpret_cast<uint8_t *>(argv[i]), strlen(argv[i])});
  }
}
} // namespace polytracker