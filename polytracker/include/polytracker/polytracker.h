#ifndef __POLYTRACKER_H__
#define __POLYTRACKER_H__
#include "polytracker/dfsan_types.h"
// NOTE: Whenever the version is updated, make sure to add support to the JSON
// parsing code in polytracker.py!

#define POLYTRACKER_VERSION_MAJOR 3
#define POLYTRACKER_VERSION_MINOR 1
#define POLYTRACKER_VERSION_REVISION 0

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

// Mapping from function name to id, created by polytracker-pass
struct func_mapping {
  char *func_name;
  uint32_t id;
};

// Block function-id and type representations, created by polytracker-pass
struct block_mapping {
  uint64_t func_bb;
  uint8_t btype;
};

void polytracker_end();
void polytracker_start(func_mapping const *globals, uint64_t globals_count,
                       block_mapping const *block_map, uint64_t block_map_count,
                       bool control_flow_tracking);

extern const func_mapping *func_mappings;
extern uint64_t func_mapping_count;

extern const block_mapping *block_mappings;
extern uint64_t block_mapping_count;
