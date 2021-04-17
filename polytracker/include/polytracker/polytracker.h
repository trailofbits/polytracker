#ifndef __POLYTRACKER_H__
#define __POLYTRACKER_H__
#include "polytracker/dfsan_types.h"
// NOTE: Whenever the version is updated, make sure to add support to the JSON
// parsing code in polytracker.py!

#define POLYTRACKER_VERSION_MAJOR 3
#define POLYTRACKER_VERSION_MINOR 0
#define POLYTRACKER_VERSION_REVISION 2

// If there is a suffix, it should always start with a hypen, like "-alpha2.2".
// If there is no suffix, set POLYTRACKER_VERSION_SUFFIX to an empty string.
#define POLYTRACKER_VERSION_SUFFIX ""

/**********************************************************************************/

#define PF_STR_HELPER(s) #s
#define PF_MAKE_STR(s) PF_STR_HELPER(s)

#define POLYTRACKER_VERSION                                                    \
  PF_MAKE_STR(POLYTRACKER_VERSION_MAJOR)                                       \
  "." PF_MAKE_STR(POLYTRACKER_VERSION_MINOR) "." PF_MAKE_STR(                  \
      POLYTRACKER_VERSION_REVISION) POLYTRACKER_VERSION_SUFFIX

#endif

void polytracker_end();