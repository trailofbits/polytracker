#ifndef POLYTRACKER_LOGGING
#define POLYTRACKER_LOGGING
#include "dfsan/dfsan_types.h"
#include "polytracker/tracing.h"

//TODO change to enum
#define UNKNOWN_EVENT_ID -1
#define INPUT_ACCESS_TYPE 0
#define CMP_ACCESS_TYPE 1

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
tFuncStack is the current call stack which records calls/returns to create the
runtime cfg tainted_funcs_all_ops is a map from function_name --> set<labels>
that the function operated on tainted_funcs_cmp is the same thing but we wanted
to make comparisons special and denote it, this might be removed later once we
do basic block summarization the runtime cfg is the flow sensitive runtime
control flow graph
*/
struct RuntimeInfo {
  //std::vector<func_index_t> tFuncStack;
  //std::unordered_map<func_index_t, std::unordered_set<dfsan_label>> tainted_funcs_all_ops;
  //std::unordered_map<func_index_t, std::unordered_set<dfsan_label>> tainted_funcs_cmp;
  //std::unordered_map<func_index_t, std::unordered_set<func_index_t>> runtime_cfg;
  std::unordered_map<std::string, BBIndex> func_name_to_index;
  polytracker::Trace trace;
};
#endif
