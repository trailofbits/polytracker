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
thread_local std::stack<event_id_t> function_stack;
thread_local int thread_id = -1;
thread_local event_id_t thread_event_id = 0;
std::atomic<event_id_t> event_id = 0;
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
  const auto this_event_id = event_id++;
  storeTaintAccess(output_db, label, this_event_id, thread_event_id++, findex,
                   bindex, input_id, thread_id, ByteAccessType::CMP_ACCESS,
                   function_stack.empty() ? this_event_id
                                          : function_stack.back());
}

void logOperation(const dfsan_label &label, const function_id_t &findex,
                  const block_id_t &bindex) {
  const auto this_event_id = event_id++;
  storeTaintAccess(output_db, label, event_id++, thread_event_id++, findex,
                   bindex, input_id, thread_id, ByteAccessType::INPUT_ACCESS,
                   function_stack.empty() ? this_event_id
                                          : function_stack.back());
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
  const auto this_event_id = event_id++;
  storeFuncCFGEdge(output_db, input_id, thread_id, func_id, curr_func_index,
                   this_event_id, EdgeType::FORWARD);
  storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
             EventType::FUNC_ENTER, func_id, 0, this_event_id);
  function_stack.push(this_event_id);
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
    const auto this_event_id = event_id++;
    storeFuncCFGEdge(output_db, input_id, thread_id, index, curr_func_index,
                     this_event_id, EdgeType::BACKWARD);
    event_id_t current_function_event;
    if (UNLIKELY(function_stack.empty())) {
      std::cerr
          << "Warning: Could not resolve the function entry associated with "
             "the return from function index "
          << curr_func_index << " to " << index
          << ". This is likely due to either an instrumentation error "
          << "or non-standard control-flow in the instrumented program.\n";
      current_function_event = this_event_id;
    } else {
      current_function_event = function_stack.back();
      function_stack.pop()
    }
    storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
               EventType::FUNC_RET, index, 0, current_function_event);
  }
  curr_func_index = index;
}

void logBBEntry(const char *fname, const function_id_t &findex,
                const block_id_t &bindex, const uint8_t &btype) {
  assignThreadID();
  // NOTE (Carson) we could memoize this to prevent repeated calls for loop
  // blocks
  storeBlock(output_db, findex, bindex, btype);
  const auto this_event_id = event_id++;
  storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
             EventType::BLOCK_ENTER, findex, bindex,
             function_stack.empty() ? this_event_id : function_stack.back());
  curr_block_index = bindex;
}
