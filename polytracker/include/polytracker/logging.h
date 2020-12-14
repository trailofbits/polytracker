#ifndef POLYTRACKER_LOGGING
#define POLYTRACKER_LOGGING
#include "dfsan/dfsan_types.h"
#include "polytracker/tracing.h"

using namespace polytracker;

[[nodiscard]] taint_node_t *getTaintNode(dfsan_label label);
[[nodiscard]] dfsan_label getTaintLabel(taint_node_t *node);
void logOperation(dfsan_label some_label);
void logCompare(dfsan_label some_label);
void resetFrame(int* index);
void logFunctionEntry(const char* fname, BBIndex index);
void logFunctionExit(BBIndex index);
void logBBEntry(const char* fname, BBIndex bbIndex, BasicBlockType bbType);
[[nodiscard]] bool getFuncIndex(const std::string& func_name, BBIndex & index);

/*
Each thread has a threadlocal variable which represents its runtime state.
*/
struct RuntimeInfo {
  std::unordered_map<std::string, BBIndex> func_name_to_index;
  polytracker::Trace trace;
};
#endif
