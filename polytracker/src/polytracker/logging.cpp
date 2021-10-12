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
thread_local function_id_t curr_func_index = -1;
thread_local FunctionStack function_stack;
thread_local int thread_id = -1;
thread_local event_id_t thread_event_id = 0;
thread_local event_id_t last_bb_event_id = 0;
std::atomic<event_id_t> event_id{0};
std::atomic<size_t> last_thread_id{0};

static void inline assignThreadID() {
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

void logCompare(const dfsan_label label, const function_id_t findex,
                const block_id_t bindex) {
  storeTaintAccess(output_db, label, input_id, ByteAccessType::CMP_ACCESS);
}

void logOperation(const dfsan_label label, const function_id_t findex,
                  const block_id_t bindex) {
  storeTaintAccess(output_db, label, input_id, ByteAccessType::INPUT_ACCESS);
}

void logCallUninst(const function_id_t func_id, const block_id_t block_id,
                   const char *fname) {
  const auto this_event_id = event_id++;
  storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
             EventType::CALL_UNINST, func_id, block_id,
             function_stack.back().func_event_id);
  storeUninstFuncEntry(output_db, this_event_id, fname);
}

void logCallIndirect(const function_id_t func_id, const block_id_t block_id) {
  const auto this_event_id = event_id++;
  storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
             EventType::CALL_INDIRECT, func_id, block_id,
             function_stack.back().func_event_id);
}

int logFunctionEntry(const function_id_t func_id) {
  assignThreadID();
  // Func CFG edges added by funcExit (as it knows the return location)
  const auto this_event_id = event_id++;
  // FIXME (Evan): the function CFG shouldn't store event IDs because we can
  // reconstruct that from the events
  storeFuncCFGEdge(output_db, input_id, thread_id, func_id, curr_func_index,
                   this_event_id, EdgeType::FORWARD);
  storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
             EventType::FUNC_ENTER, func_id, 0, this_event_id);
  function_stack.push_back({this_event_id, func_id, {}, false});
  curr_func_index = func_id;
  return function_stack.size();
}

// Handles stack jumps
void logCallExit(const function_id_t index, const int stack_loc) {
  while (UNLIKELY(stack_loc < function_stack.size())) {
    const auto &current_function_event = function_stack.back().func_event_id;
    const auto &func_index = function_stack.back().func_id;
    const auto &this_event_id = event_id++;
    function_stack.pop_back();
    storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
               EventType::FUNC_RET, func_index, 0, current_function_event);
  }
  curr_func_index = index;
}

void logFunctionExit(const function_id_t index, const int stack_loc) {
  // The function stack should never be empty, as a logFunctionExit should have
  // a corresponding logFunctionEntry
  const auto &current_function_event = function_stack.back().func_event_id;
  const auto &func_index = function_stack.back().func_id;
  const auto &this_event_id = event_id++;
  function_stack.pop_back();
  storeEvent(output_db, input_id, thread_id, this_event_id, thread_event_id++,
             EventType::FUNC_RET, func_index, 0, current_function_event);
  curr_func_index = index;
}

void logBBEntry(const function_id_t findex, const block_id_t bindex,
                const uint8_t btype) {
  assignThreadID();
  last_bb_event_id = event_id++;
  // uint64_t gid = static_cast<uint64_t>(findex) << 32 | bindex;
  // std::cout << "RT hit fid: " << findex << " bid: " << bindex << " gid: " <<
  // gid
  //          << std::endl;

  auto entryCount = function_stack.back().bb_entry_count[bindex]++;
  storeBlockEntry(output_db, input_id, thread_id, last_bb_event_id,
                  thread_event_id++, findex, bindex,
                  function_stack.back().func_event_id, entryCount);
}
