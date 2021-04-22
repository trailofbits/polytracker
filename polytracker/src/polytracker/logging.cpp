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
#include <thread>
#include <tuple>
#include <unordered_map>

extern char *forest_mem;
extern input_id_t input_id;
extern sqlite3 *output_db;
thread_local block_id_t curr_block_index = -1;
thread_local function_id_t curr_func_index = -1;
thread_local FunctionStack function_stack;
thread_local int thread_id = -1;
thread_local event_id_t thread_event_id = 0;
thread_local event_id_t last_bb_event_id = 0;
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

void logCompare(const dfsan_label &label, const function_id_t findex,
                const block_id_t bindex) {
  storeTaintAccess(output_db, label, input_id, ByteAccessType::CMP_ACCESS);
}

void logOperation(const dfsan_label &label, const function_id_t findex,
                  const block_id_t bindex) {
  storeTaintAccess(output_db, label, input_id, ByteAccessType::INPUT_ACCESS);
}

void logFuncCall(const char *targ_name, const function_id_t findex,
                 const block_id_t bindex) {
  const auto this_event_id = event_id++;
  storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
             EventType::FUNC_CALL, findex, bindex, this_event_id);

  storeFuncCall(output_db, input_id, thread_id, this_event_id,
                thread_event_id++, targ_name);
  // function_stack.push({this_event_id, findex, {}});
}

void logFunctionEntry(const char *fname, const function_id_t func_id) {
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
  // std::cerr << "logFunctionEntry(" << fname << ", " << func_id << ")\n";
  // TODO (Carson) for Evan, its just a check quick to assign a thread_id.
  assignThreadID();
  // This just stores a mapping, should be true for all runs.
  storeFunc(output_db, fname, func_id);
  // Func CFG edges added by funcExit (as it knows the return location)
  const auto this_event_id = event_id++;
  /*
  storeFuncCFGEdge(output_db, input_id, thread_id, func_id, curr_func_index,
                   this_event_id, EdgeType::FORWARD);
  */
  storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
             EventType::FUNC_ENTER, func_id, 0, this_event_id);
  function_stack.push({this_event_id, func_id, {}});
  curr_func_index = func_id;
}

std::string funcName(const function_id_t index) {
  auto funcName = getFuncName(output_db, index);
  if (!funcName.empty()) {
    funcName = "`" + funcName + "` ";
  }
  return funcName + std::string("index ") + std::to_string(index);
}

void logFunctionExit(const function_id_t index) {
  if (UNLIKELY(!is_init)) {
    return;
  } else if (UNLIKELY(function_stack.empty() ||
                      function_stack.top().func_id != curr_func_index)) {
    std::cerr
        << "Warning: Could not resolve the function entry associated with "
           "the return from function "
        << funcName(curr_func_index) << " to " << funcName(index);
    if (!function_stack.empty()) {
      std::cerr << " (expected to be returning from function "
                << funcName(function_stack.top().func_id) << ")";
    }
    std::cerr << ". This is likely due to either an instrumentation error "
              << "or non-standard control-flow in the instrumented program.\n";
  } else {
    const auto current_function_event = function_stack.top().func_event_id;
    const auto this_event_id = event_id++;
    // std::cerr << "logFunctionExit(" << index << ") event_id = " <<
    // this_event_id <<
    //              ", curr_func_index = " << curr_func_index <<
    //              ", current_function_event = " << current_function_event <<
    //              "\n";
    /*
    storeFuncCFGEdge(output_db, input_id, thread_id, index, curr_func_index,
                     this_event_id, EdgeType::BACKWARD);
    */
    function_stack.pop();
    storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
               EventType::FUNC_RET, curr_func_index, 0, current_function_event);
  }
  curr_func_index = index;
}

void logBBEntry(const char *fname, const function_id_t findex,
                const block_id_t bindex, const uint8_t &btype) {
  assignThreadID();
  // NOTE (Carson) we could memoize this to prevent repeated calls for loop
  // blocks
  storeBlock(output_db, findex, bindex, btype);
  last_bb_event_id = event_id++;
  auto entryCount = function_stack.top().bb_entry_count[bindex]++;
  storeBlockEntry(output_db, input_id, thread_id, last_bb_event_id,
                  thread_event_id++, findex, bindex,
                  function_stack.empty() ? last_bb_event_id
                                         : function_stack.top().func_event_id,
                  entryCount);
  curr_block_index = bindex;
}
