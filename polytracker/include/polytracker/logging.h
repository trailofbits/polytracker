#ifndef POLYTRACKER_LOGGING
#define POLYTRACKER_LOGGING 
#include "polytracker/tracing.h"
#include "dfsan/dfsan_types.h"

using namespace polytracker; 

[[nodiscard]] taint_node_t* getTaintNode(dfsan_label label);
[[nodiscard]] dfsan_label getTaintLabel(taint_node_t* node);
void logOperation(dfsan_label some_label);
void logComparison(dfsan_label some_label);
void resetFrame(int* index);
int logFunctionEntry(const char* fname);
void logFunctionExit();
void logBBEntry(const char* fname, BBIndex bbIndex, BasicBlockType bbType);
/*
[[nodiscard]] static inline auto getTaintFuncOps(void) -> std::unordered_map<const char *, std::unordered_set<dfsan_label>>&;
[[nodiscard]] static inline auto getTaintFuncCmps(void) -> std::unordered_map<const char *, std::unordered_set<dfsan_label>>&;
[[nodiscard]] static inline auto getRuntimeCfg(void) -> std::unordered_map<const char*, std::unordered_set<const char *>>&;
[[nodiscard]] static inline auto getPolytrackerTrace(void) -> polytracker::Trace&;
*/
/*
Each thread has a threadlocal variable which represents its runtime state. 
tFuncStack is the current call stack which records calls/returns to create the runtime cfg 
tainted_funcs_all_ops is a map from function_name --> set<labels> that the function operated on 
tainted_funcs_cmp is the same thing but we wanted to make comparisons special and denote it, this might be removed later 
once we do basic block summarization
the runtime cfg is the flow sensitive runtime control flow graph  
*/
struct RuntimeInfo {
  std::vector<const char *> tFuncStack;
  polytracker::Trace trace;
  std::unordered_map<const char *, std::unordered_set<dfsan_label>> tainted_funcs_all_ops;
  std::unordered_map<const char *, std::unordered_set<dfsan_label>> tainted_funcs_cmp;
  std::unordered_map<const char*, std::unordered_set<const char *>> runtime_cfg;
};
#endif