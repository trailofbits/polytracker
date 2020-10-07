#ifndef POLYTRACKER_LOGGING
#define POLYTRACKER_LOGGING 
#include "include/dfsan/dfsan_types.h"
inline taint_node_t* getTaintNode(dfsan_label label);
inline dfsan_label getTaintLabel(taint_node_t* node);
#endif