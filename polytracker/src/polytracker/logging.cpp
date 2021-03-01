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

extern char *forest_mem;
extern bool polytracker_trace;
extern bool polytracker_trace_func;

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
  std::cout << "Initing thread info!" << std::endl;
  runtime_info = new RuntimeInfo();
  std::lock_guard<std::mutex> locker(thread_runtime_info_lock);
  thread_runtime_info.push_back(runtime_info);
  std::cout << "Thread info size is: " << thread_runtime_info.size() << std::endl;
}

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
  if (polytracker_trace_func) {
    polytracker::Trace &trace = getPolytrackerTrace();
    trace.funcAddTaintLabel(some_label, CMP_ACCESS);
  }
  
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
  if (polytracker_trace_func) {
    polytracker::Trace &trace = getPolytrackerTrace();
    #ifdef DEBUG_INFO    
    bool res = trace.funcAddTaintLabel(some_label, CMP_ACCESS);
    if (res == false) {
      std::cerr << "Failed to add taint label!" << std::endl;
    }
    #else 
    trace.funcAddTaintLabel(some_label, INPUT_ACCESS);
    #endif
  }
  
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


thread_local bool ret_or_longjmp = false;
void traceFunctionEntry(BBIndex index) {
  polytracker::Trace &trace = getPolytrackerTrace();
  //If there were returns, first push a cont object.
  if (ret_or_longjmp) {
    trace.functionEvents.emplace_back(trace.currentFunc()->index, true);
    ret_or_longjmp = false;
  }
  trace.functionEvents.emplace_back(index, false);
}
void traceAddContinuation(BBIndex index) {
  ret_or_longjmp = true;
}


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
  auto& func_index_map = getIndexMap();
  func_index_map[fname] = index;

  if (polytracker_trace_func) {
    traceFunctionEntry(index);
  }
    if (polytracker_trace) {
      polytracker::Trace &trace = getPolytrackerTrace();
      auto &stack = trace.getStack(std::this_thread::get_id());
      auto call = stack.emplace<FunctionCall>(fname);
      // Create a new stack frame:
      stack.newFrame(call);
    }
}

void logFunctionExit(BBIndex index) {
  if (UNLIKELY(!is_init)) {
    return;
  }
  if (polytracker_trace_func) {
    traceAddContinuation(index);
  }
  if (polytracker_trace) {
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