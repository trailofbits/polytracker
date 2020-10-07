#include "include/dfsan/dfsan_log_mgmt.h"
#include "sanitizer_common/sanitizer_common.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <set>
#include <stack>
#include <tuple>

using json = nlohmann::json;

using polytracker::BasicBlockEntry;
using polytracker::BasicBlockType;
using polytracker::FunctionCall;
using polytracker::FunctionReturn;
using polytracker::hasType;
using polytracker::TraceEvent;
using namespace __dfsan;

extern const char * shad_mem_ptr; 
extern const char * forest_mem; 
extern bool polytracker_trace;

//TODO This might be moved to the public facing funcs file 
//std::mutex taint_lock;
std::unordered_map<std::thread::id, std::vector<std::string>> func_stack_map; 

static thread_local std::vector<const char *> tFuncStack;
static thread_local polytracker::Trace trace;
static thread_local std::unordered_map<const char *, std::unordered_set<dfsan_label>> tainted_funcs_all_ops;
static thread_local std::unordered_map<const char *, std::unordered_set<dfsan_label>> tainted_funcs_cmp;
static thread_local std::unordered_map<const char*, std::unordered_set<const char *>> runtime_cfg;


static inline std::vector<const char *>& GetFuncStack(void) {
  return tFuncStack;
}

inline taint_node_t* getTaintNode(dfsan_label label) {
  taint_node_t* ret_node =
      (taint_node_t*)(forest_mem + (label * sizeof(taint_node_t)));
  return ret_node;
}

inline dfsan_label getTaintLabel(taint_node_t* node) {
  dfsan_label ret_label = ((char*)node - forest_mem) / sizeof(taint_node_t);
  return ret_label;
}

void logCompare(dfsan_label some_label) {
  if (some_label == 0) {
    return;
  }
  auto curr_node = getTaintNode(some_label); 
  std::vector<const char *>& func_stack = GetFuncStack();
  tainted_funcs_cmp[func_stack.back()].insert(some_label);
  //TODO Confirm that we only call logCmp once instead of logOp along with it. 
  tainted_funcs_all_ops[func_stack.back()].insert(some_label);
  if (auto bb = trace.currentBB()) {
    // we are recording a full trace, and we know the current basic block
    if (curr_node->p1 == nullptr && curr_node->p2 == nullptr) {
      // this is a canonical label
      trace.setLastUsage(some_label, bb);
    }
  }
}

void logOperation(dfsan_label some_label) {
  if (some_label == 0) {
      return;
  }
  std::vector<const char *>& func_stack = GetFuncStack();
  tainted_funcs_all_ops[func_stack.back()].insert(some_label);
  if (auto bb = trace.currentBB()) {
    taint_node_t* new_node = getTaintNode(some_label);
    // we are recording a full trace, and we know the current basic block
    if (new_node->p1 == nullptr && new_node->p2 == nullptr) {
      // this is a canonical label
      trace.setLastUsage(some_label, bb);
    }
  }
}

int logFunctionEntry(const char* fname) {
  //Lots of object creations etc. 
  std::vector<const char *>& func_stack = GetFuncStack();
  if (func_stack.size() > 0) {
      runtime_cfg[fname].insert(func_stack.back());
  }
  else {
      runtime_cfg[fname].insert(func_stack.back());
  }
  func_stack.push_back(fname);
  if (polytracker_trace) {
    auto& stack = trace.getStack(std::this_thread::get_id());
    auto call = stack.emplace<FunctionCall>(fname);
    // Create a new stack frame:
    stack.newFrame(call);
  }
  return func_stack.size() - 1;
}

void logFunctionExit() {
  std::vector<const char *>& func_stack = GetFuncStack();
  func_stack.pop_back();
  if (polytracker_trace) {
    auto& stack = trace.getStack(std::this_thread::get_id());
    if (!stack.pop()) {
      // if this happens, then stack should have been a null pointer,
      // which would have likely caused a segfault before this!
      // FIXME: Figure out why simply printing a string here causes a segfault
      //        in jq
      // std::cerr << "Event stack was unexpectedly empty!" << std::endl;
    } else {
      if (auto func = dynamic_cast<FunctionCall*>(stack.peek().peek())) {
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
void logBBEntry(char* fname, BBIndex bbIndex,
                              BasicBlockType bbType) {
  auto currentStack = trace.currentStack();
  BasicBlockEntry* newBB;
  if (auto prevBB = currentStack->peek().lastOccurrence(bbIndex)) {
    // this is not the first occurrence of this basic block in the current
    // stack frame
    newBB = currentStack->emplace<BasicBlockEntry>(
        fname, bbIndex, prevBB->entryCount + 1, bbType);
  } else {
    newBB = currentStack->emplace<BasicBlockEntry>(fname, bbIndex, bbType);
  }
  if (auto ret = dynamic_cast<FunctionReturn*>(newBB->previous)) {
    ret->returningTo = newBB;
  }
}

void resetFrame(int* index) {
  if (index == nullptr) {
    std::cout
        << "Pointer to array index is null! Instrumentation error, aborting!"
        << std::endl;
    abort();
  }
  std::vector<const char *>& func_stack = GetFuncStack();
  const char * caller_func = GetFuncStack().back();
  // Reset the frame
  func_stack.resize(*index + 1);
  runtime_cfg[func_stack.back()].insert(caller_func);
}

dfsan_label taintManager::createReturnLabel(int file_byte_offset,
                                            std::string name) {
  taint_prop_lock.lock();
  dfsan_label ret_label = createCanonicalLabel(file_byte_offset, name);
  taint_bytes_processed[name].push_back(
      std::pair<int, int>(file_byte_offset, file_byte_offset));
  taint_prop_lock.unlock();
  return ret_label;
}

dfsan_label taintManager::createCanonicalLabel(int file_byte_offset,
                                               std::string name) {
  dfsan_label new_label = next_label;
  next_label += 1;
  checkMaxLabel(new_label);
  taint_node_t* new_node = getTaintNode(new_label);
  new_node->p1 = NULL;
  new_node->p2 = NULL;
  new_node->decay = taint_node_ttl;
  canonical_mapping[name][new_label] = file_byte_offset;
  return new_label;
}

bool taintManager::taintData(int fd, char* mem, int offset, int len) {
  taint_prop_lock.lock();
  if (!isTracking(fd)) {
    taint_prop_lock.unlock();
    return false;
  }
  targetInfo* targ_info = getTargetInfo(fd);
  taintTargetRange(mem, offset, len, targ_info->byte_start, targ_info->byte_end,
                   targ_info->target_name);
  taint_prop_lock.unlock();
  return true;
}

bool taintManager::taintData(FILE* fd, char* mem, int offset, int len) {
  taint_prop_lock.lock();
  if (!isTracking(fd)) {
    taint_prop_lock.unlock();
    return false;
  }
  targetInfo* targ_info = getTargetInfo(fd);
  taintTargetRange(mem, offset, len, targ_info->byte_start, targ_info->byte_end,
                   targ_info->target_name);
  taint_prop_lock.unlock();
  return true;
}
/*
 * This function is responsible for marking memory locations as tainted, and is
 * called when taint is processed by functions like read, pread, mmap, recv,
 * etc.
 *
 * Mem is a pointer to the data we want to taint
 * Offset tells us at what point in the stream/file we are in (before we read)
 * Len tells us how much we just read in
 * byte_start and byte_end are target specific options that allow us to only
 * taint specific regions like (0-100) etc etc
 *
 * If a byte is supposed to be tainted we make a new taint label for it, these
 * labels are assigned sequentially.
 *
 * Then, we keep track of what canonical labels map to what original file
 * offsets.
 *
 * Then we update the shadow memory region with the new label
 */
void taintManager::taintTargetRange(char* mem, int offset, int len,
                                    int byte_start, int byte_end,
                                    std::string name) {
  int curr_byte_num = offset;
  int taint_offset_start = -1, taint_offset_end = -1;
  bool processed_bytes = false;
  for (char* curr_byte = (char*)mem; curr_byte_num < offset + len;
       curr_byte_num++, curr_byte++) {
    // If byte end is < 0, then we don't care about ranges.
    if (byte_end < 0 ||
        (curr_byte_num >= byte_start && curr_byte_num <= byte_end)) {
      dfsan_label new_label = createCanonicalLabel(curr_byte_num, name);
      dfsan_set_label(new_label, curr_byte, TAINT_GRANULARITY);

      // Log that we tainted data within this function from a taint source etc.
      logTaintedData(new_label);
      if (taint_offset_start == -1) {
        taint_offset_start = curr_byte_num;
        taint_offset_end = curr_byte_num;
      } else if (curr_byte_num > taint_offset_end) {
        taint_offset_end = curr_byte_num;
      }
      processed_bytes = true;
    }
  }
  if (processed_bytes) {
    taint_bytes_processed[name].push_back(
        std::pair<int, int>(taint_offset_start, taint_offset_end));
  }
}

dfsan_label taintManager::_unionLabel(dfsan_label l1, dfsan_label l2,
                                      decay_val init_decay) {
  dfsan_label ret_label = next_label;
  next_label += 1;
  checkMaxLabel(ret_label);
  taint_node_t* new_node = getTaintNode(ret_label);
  new_node->p1 = getTaintNode(l1);
  new_node->p2 = getTaintNode(l2);
  new_node->decay = init_decay;
  return ret_label;
}

dfsan_label taintManager::createUnionLabel(dfsan_label l1, dfsan_label l2) {
  taint_prop_lock.lock();
  // If sanitizer debug is on, this checks that l1 != l2
  DCHECK_NE(l1, l2);
  if (l1 == 0) {
    taint_prop_lock.unlock();
    return l2;
  }
  if (l2 == 0) {
    taint_prop_lock.unlock();
    return l1;
  }
  if (l1 > l2) {
    Swap(l1, l2);
  }
  // Quick union table check
  if ((union_table[l1]).find(l2) != (union_table[l1]).end()) {
    auto val = union_table[l1].find(l2);
    taint_prop_lock.unlock();
    return val->second;
  }
  // Check for max decay
  taint_node_t* p1 = getTaintNode(l1);
  taint_node_t* p2 = getTaintNode(l2);
  // This calculates the average of the two decays, and then decreases it by a
  // factor of 2.
  decay_val max_decay = (p1->decay + p2->decay) / 4;
  if (max_decay == 0) {
    taint_prop_lock.unlock();
    return 0;
  }
  dfsan_label label = _unionLabel(l1, l2, max_decay);
  (union_table[l1])[l2] = label;
  taint_prop_lock.unlock();
  return label;
}

void taintManager::checkMaxLabel(dfsan_label label) {
  if (label == MAX_LABELS) {
    std::cout << "ERROR: MAX LABEL REACHED, ABORTING!" << std::endl;
    // Cant exit due to our exit handlers
    abort();
  }
}

dfsan_label taintManager::getLastLabel() {
  taint_prop_lock.lock();
  dfsan_label last_label = next_label - 1;
  taint_prop_lock.unlock();
  return last_label;
}
