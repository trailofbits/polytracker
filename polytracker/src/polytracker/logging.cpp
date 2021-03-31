#include "polytracker/logging.h"
#include "polytracker/main.h"
#include "polytracker/output.h"
#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <set>
#include <stack>
#include <thread>
#include <tuple>
#include <unordered_map>

extern char *forest_mem;
extern input_id_t input_id;
extern sqlite3 *output_db;
thread_local block_id_t curr_block_index = -1;
thread_local function_id_t curr_func_index = -1;
thread_local int thread_id = -1;
thread_local event_id_t event_id = 0;
std::atomic<size_t> last_thread_id{0};
static bool is_init = false;
std::mutex is_init_mutex;

static void assignThreadID() {
  if (UNLIKELY(thread_id == -1)) {
    thread_id = last_thread_id.fetch_add(1) + 1;
  }
}

[[nodiscard]] taint_node_t *getTaintNode(dfsan_label label) {
  return (taint_node_t *)(forest_mem + (label * sizeof(taint_node_t)));
}

[[nodiscard]] dfsan_label getTaintLabel(taint_node_t *node) {
  return (dfsan_label)(((char *)node - forest_mem) / sizeof(taint_node_t));
}

void logCompare(const dfsan_label &label, const function_id_t &findex,
                const block_id_t &bindex) {
  storeTaintAccess(output_db, label, event_id++, findex, bindex, input_id,
                   thread_id, ByteAccessType::CMP_ACCESS);
}

void logOperation(const dfsan_label &label, const function_id_t &findex,
                  const block_id_t &bindex) {
  storeTaintAccess(output_db, label, event_id++, findex, bindex, input_id,
                   thread_id, ByteAccessType::INPUT_ACCESS);
}

thread_local bool recursive = false;
thread_local std::unordered_map<function_id_t, bool> recursive_funcs;

void logFunctionEntry(const char *fname, const function_id_t &func_id) {
  // The pre init/init array hasn't played friendly with our use of C++
  // For example, the bucket count for unordered_map is 0 when accessing one
  // during the init phase
  if (UNLIKELY(!is_init)) {
    if (strcmp(fname, "main") != 0) {
      return;
    }
    is_init = true;
    polytracker_start();
  }
  // TODO (Carson) for Evan, its just a check quick to assign a thread_id.
  assignThreadID();
  // This just stores a mapping, should be true for all runs.
  storeFunc(output_db, fname, func_id);
  // Func CFG edges added by funcExit (as it knows the return location)
  storeFuncCFGEdge(output_db, input_id, thread_id, func_id, curr_func_index,
                   event_id++, EdgeType::FORWARD);
  storeEvent(output_db, input_id, thread_id, event_id, EventType::FUNC_ENTER,
             func_id, 0);
  if (UNLIKELY(func_id == curr_func_index)) {
    recursive_funcs[func_id] = true;
  }
  curr_func_index = func_id;
}

void logFunctionExit(const function_id_t &index) {
  if (UNLIKELY(!is_init)) {
    return;
  }
  // Here, the curr_func_index is from the function we just returned from
  // NOTE (Carson) the map makes sure we don't add accidental recursive edges
  // due to missing instrumentation Draw return edge from curr_func_index -->
  // index
  if (curr_func_index != index ||
      (recursive_funcs.find(curr_func_index) != recursive_funcs.end())) {
    storeFuncCFGEdge(output_db, input_id, thread_id, index, curr_func_index,
                     event_id++, EdgeType::BACKWARD);
    storeEvent(output_db, input_id, thread_id, event_id, EventType::FUNC_RET,
               index, 0);
  }
  curr_func_index = index;
}

void logBBEntry(const char *fname, const function_id_t &findex,
                const block_id_t &bindex, const uint8_t &btype) {
  assignThreadID();
  // NOTE (Carson) we could memoize this to prevent repeated calls for loop
  // blocks
  storeBlock(output_db, findex, bindex, btype);
  storeEvent(output_db, input_id, thread_id, event_id++, EventType::BLOCK_ENTER,
             findex, bindex);
  curr_block_index = bindex;
}