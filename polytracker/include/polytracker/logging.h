#ifndef POLYTRACKER_LOGGING
#define POLYTRACKER_LOGGING
#include "dfsan_types.h"
#include "polytracker/output.h"

[[nodiscard]] taint_node_t *getTaintNode(dfsan_label label);
[[nodiscard]] dfsan_label getTaintLabel(taint_node_t *node);
[[nodiscard]] bool getFuncIndex(const std::string& func_name, BBIndex & index);

void logCompare(const dfsan_label& label, const function_id_t& findex, const block_id_t& bindex);
void logOperation(const dfsan_label& label, const function_id_t& findex, const block_id_t& bindex);
void logFunctionEntry(const char *fname, const function_id_t& func_id);
void logFunctionExit(const function_id_t& index);
void logBBEntry(const char *fname, const function_id_t& findex, const block_id_t& bindex, const uint8_t& btype);

#define LIKELY(x)      __builtin_expect(!!(x), 1)
#define UNLIKELY(x)    __builtin_expect(!!(x), 0)
#endif