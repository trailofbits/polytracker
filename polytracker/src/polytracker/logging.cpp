#include "polytracker/logging.h"
#include "polytracker/main.h"
#include "polytracker/tracing.h"
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <set>
#include <stack>
#include <thread>
#include <tuple>

using polytracker::BasicBlockEntry;
using polytracker::BasicBlockType;
using polytracker::FunctionCall;
using polytracker::FunctionReturn;
using polytracker::hasType;
using polytracker::TraceEvent;
using namespace __dfsan;

extern char *forest_mem;
extern bool polytracker_trace;

thread_local RuntimeInfo *runtime_info = nullptr;

// To access all information from the different threads, at the end of execution
// we iterate through this vector that stores all the thread info and dump it to
// disk as raw, json, and eventually to a sqldb
std::vector<RuntimeInfo *> thread_runtime_info;
std::mutex thread_runtime_info_lock;

static bool is_init = false;
std::mutex is_init_mutex;

/*
This function should only be called once per thread, but it initializes the
thread local storage And stores the pointer to it in the vector.
*/
static void initThreadInfo() {
  runtime_info = new RuntimeInfo();
  std::lock_guard<std::mutex> locker(thread_runtime_info_lock);
  thread_runtime_info.push_back(runtime_info);
}
/*
[[nodiscard]] static inline std::vector<func_index_t> &getFuncStack(void) {
  if (UNLIKELY(!runtime_info)) {
    initThreadInfo();
  }
  return runtime_info->tFuncStack;
}

[[nodiscard]] static inline auto getTaintFuncOps(void)
    -> std::unordered_map<func_index_t, std::unordered_set<dfsan_label>> & {
  if (UNLIKELY(!runtime_info)) {
    initThreadInfo();
  }
  return runtime_info->tainted_funcs_all_ops;
}

[[nodiscard]] static inline auto getTaintFuncCmps(void)
    -> std::unordered_map<func_index_t, std::unordered_set<dfsan_label>> & {
  if (UNLIKELY(!runtime_info)) {
    initThreadInfo();
  }
  return runtime_info->tainted_funcs_cmp;
}

[[nodiscard]] static inline auto getRuntimeCfg(void)
    -> std::unordered_map<func_index_t, std::unordered_set<func_index_t>> & {
  if (UNLIKELY(!runtime_info)) {
    initThreadInfo();
  }
  return runtime_info->runtime_cfg;
}
*/
[[nodiscard]] taint_node_t *getTaintNode(dfsan_label label) {
  return (taint_node_t *)(forest_mem + (label * sizeof(taint_node_t)));
}

[[nodiscard]] dfsan_label getTaintLabel(taint_node_t *node) {
  return (dfsan_label)(((char *)node - forest_mem) / sizeof(taint_node_t));
}

[[nodiscard]] static inline auto getPolytrackerTrace(void)
    -> polytracker::Trace & {
  if (UNLIKELY(!runtime_info)) {
    initThreadInfo();
  }
  return runtime_info->trace;
}
[[nodiscard]] auto getIndexMap(void) -> std::unordered_map<std::string, BBIndex>& {
	if (UNLIKELY(!runtime_info)) {
	    initThreadInfo();
	}
	return runtime_info->func_name_to_index;
}

[[nodiscard]] bool getFuncIndex(const std::string& func_name, BBIndex& index) {
	if (runtime_info->func_name_to_index.find(func_name) != runtime_info->func_name_to_index.end()) {
		index = runtime_info->func_name_to_index[func_name];
		return true;
	}
	return false;
}

void logCompare(dfsan_label some_label) {
  if (some_label == 0) {
    return;
  }
  //polytracker::Trace &trace = getPolytrackerTrace();

  //std::vector<func_index_t> &func_stack = getFuncStack();
  //getTaintFuncOps()[func_stack.back()].insert(some_label);
  //getTaintFuncCmps()[func_stack.back()].insert(some_label);
  //Define some function level events. 
  if (polytracker_trace) {
    polytracker::Trace &trace = getPolytrackerTrace();
    if (auto bb = trace.currentBB()) {
        auto curr_node = getTaintNode(some_label);
      // we are recording a full trace, and we know the current basic block
      if (curr_node->p1 == nullptr && curr_node->p2 == nullptr) {
        // this is a canonical label
        trace.setLastUsage(some_label, bb);
      }
    }
  }
}

void logOperation(dfsan_label some_label) {
  if (some_label == 0) {
    return;
  }
  
  //std::vector<func_index_t> &func_stack = getFuncStack();
  //getTaintFuncOps()[func_stack.back()].insert(some_label);
  
  if (polytracker_trace) {
    polytracker::Trace &trace = getPolytrackerTrace();
    if (auto bb = trace.currentBB()) {
      taint_node_t *new_node = getTaintNode(some_label);
      // we are recording a full trace, and we know the current basic block
      if (new_node->p1 == nullptr && new_node->p2 == nullptr) {
       // this is a canonical label
       trace.setLastUsage(some_label, bb);
     }
    }
  }
}

//NOTE The return value is the index into the call stack 
//This is how we handle setjmp/longjmp, unfortunately this means 
//right now we need to maintain a call stack during polytrace, but its not a big deal 
void logFunctionEntry(const char *fname, BBIndex index) {
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
  //std::vector<uint32_t> &func_stack = getFuncStack();
  //if (func_stack.size() > 0) {
    //getRuntimeCfg()[index].insert(func_stack.back());
  //} else {
    // FIXME does this make sense?
    // -1 Can be the special entry point. 
   // getRuntimeCfg()[index].insert(-1);
  //}
  //func_stack.push_back(index);
  //getIndexMap()[fname] = index;
    //std::vector<uint32_t> &func_stack = getFuncStack();
     // func_stack.push_back(index);
    polytracker::Trace &trace = getPolytrackerTrace();
    auto &stack = trace.getStack(std::this_thread::get_id());
    auto call = stack.emplace<FunctionCall>(fname);
    // Create a new stack frame:
    stack.newFrame(call);
}

void logFunctionExit(BBIndex index) {
  if (UNLIKELY(!is_init)) {
    return;
  }
    polytracker::Trace &trace = getPolytrackerTrace();
    auto &stack = trace.getStack(std::this_thread::get_id());
    if (!stack.pop()) {
      // if this happens, then stack should have been a null pointer,
      // which would have likely caused a segfault before this!
      // FIXME: Figure out why simply printing a string here causes a segfault
      //        in jq
      // std::cerr << "Event stack was unexpectedly empty!" << std::endl;
    } else {
      if (auto func = dynamic_cast<FunctionCall *>(stack.peek().peek())) {
        // Create the function return event in the stack frame that called
        // the function
        stack.emplace<FunctionReturn>(func);
      } else {
        // FIXME: Figure out why simply printing a string here causes a segfault
        //        in jq
        // std::cerr
        //     << "Error finding matching function call in the event trace
        //     stack!";
        // if (auto bb = dynamic_cast<BasicBlockEntry*>(stack.peek().peek())) {
        //     std::cerr << " Found basic block " << bb->str() << " instead.";
        //   }
        // std::cerr << std::endl;
      }
    }
}

/**
 * This function will be called on the entry of every basic block.
 * It will only be called if polytracker_trace is true,
 * which will only be set if the POLYTRACE environment variable is set.
 */
void logBBEntry(const char *fname, BBIndex bbIndex, BasicBlockType bbType) {
  auto currentStack = getPolytrackerTrace().currentStack();
  BasicBlockEntry *newBB;
  if (auto prevBB = currentStack->peek().lastOccurrence(bbIndex)) {
    // this is not the first occurrence of this basic block in the current
    // stack frame
    newBB = currentStack->emplace<BasicBlockEntry>(
        fname, bbIndex, prevBB->entryCount + 1, bbType);
  } else {
    newBB = currentStack->emplace<BasicBlockEntry>(fname, bbIndex, bbType);
  }
  if (auto ret = dynamic_cast<FunctionReturn *>(newBB->previous)) {
    ret->returningTo = newBB;
  }
}

/*
void resetFrame(int *index) {
  if (index == nullptr) {
    std::cout
        << "Pointer to array index is null! Instrumentation error, aborting!"
        << std::endl;
    abort();
  }
  std::vector<func_index_t> &func_stack = getFuncStack();
  func_index_t caller_func = getFuncStack().back();
  // Reset the frame
  func_stack.resize(*index + 1);
  getRuntimeCfg()[func_stack.back()].insert(caller_func);
}
*/
