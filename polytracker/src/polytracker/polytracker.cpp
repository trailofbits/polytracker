#include "polytracker/polytracker.h"
#include "polytracker/logging.h"
#include "polytracker/output.h"
#include "polytracker/taint.h"
#include <atomic>
#include <inttypes.h>
#include <iostream>
#include <sanitizer/dfsan_interface.h>

extern bool polytracker_trace_func;
extern bool polytracker_trace;
extern thread_local FunctionStack function_stack;
extern sqlite3 *output_db;

const func_mapping *func_mappings;
uint64_t func_mapping_count;

const block_mapping *block_mappings;
uint64_t block_mapping_count;

// extern std::atomic_bool done;

extern "C" void __polytracker_log_taint_op(dfsan_label arg1, dfsan_label arg2,
                                           uint32_t findex, uint32_t bindex) {
  //  if (LIKELY(!done)) {
  if (LIKELY(polytracker_trace_func || polytracker_trace)) {
    if (arg1 != 0) {
      logOperation(arg1, findex, bindex);
    }
    if (arg2 != 0) {
      logOperation(arg2, findex, bindex);
    }
  }
  // }
}

extern "C" void __dfsw___polytracker_log_taint_op(
    uint32_t arg1, uint32_t arg2, uint32_t findex, uint32_t bindex,
    dfsan_label arg1_label, dfsan_label arg2_label, dfsan_label ignore_label1,
    dfsan_label ignore_label2) {
  __polytracker_log_taint_op(arg1_label, arg2_label, findex, bindex);
}

extern "C" void __polytracker_log_taint_cmp(dfsan_label arg1, dfsan_label arg2,
                                            uint32_t findex, uint32_t bindex) {

  // if (LIKELY(!done)) {
  if (LIKELY(polytracker_trace_func || polytracker_trace)) {
    if (arg1 != 0) {
      logCompare(arg1, findex, bindex);
    }
    if (arg2 != 0) {
      logCompare(arg2, findex, bindex);
    }
  }
  // }
}

extern "C" void __dfsw___polytracker_log_taint_cmp(
    uint64_t arg1, uint64_t arg2, uint32_t findex, uint32_t bindex,
    dfsan_label arg1_label, dfsan_label arg2_label, dfsan_label ignore_label1,
    dfsan_label ignore_label2) {
  __polytracker_log_taint_cmp(arg1_label, arg2_label, findex, bindex);
}

extern "C" int __polytracker_log_func_entry(uint32_t index) {
  // if (LIKELY(!done)) {
  return logFunctionEntry(index);
  // }
}

// TODO (Carson) we can use this block index if we need to.
extern "C" void __polytracker_log_func_exit(uint32_t func_index,
                                            uint32_t block_index,
                                            const int stack_loc) {
  // if (LIKELY(!done)) {
  logFunctionExit(func_index, stack_loc);
  // }
}

extern "C" void __polytracker_log_call_exit(uint32_t func_index,
                                            uint32_t block_index,
                                            const int stack_loc) {
  logCallExit(func_index, stack_loc);
}

extern "C" void __polytracker_log_call_uninst(uint32_t func_index,
                                              uint32_t block_index,
                                              char *fname) {
  logCallUninst(func_index, block_index, fname);
}

extern "C" void __polytracker_log_call_indirect(uint32_t func_index,
                                                uint32_t block_index) {
  logCallIndirect(func_index, block_index);
}

extern "C" void __polytracker_log_bb_entry(uint32_t findex, uint32_t bindex,
                                           uint8_t btype) {
  // if (polytracker_trace && LIKELY(!done)) {
  if (polytracker_trace) {
    logBBEntry(findex, bindex, btype);
  }
}

extern "C" atomic_dfsan_label *
__polytracker_union_table(const dfsan_label &l1, const dfsan_label &l2) {
  return getUnionEntry(l1, l2);
}

extern "C" void __polytracker_preserve_map(char *map) {}

extern "C" dfsan_label_info
__polytracker_get_label_info(const dfsan_label &l1) {
  taint_node_t *node = getTaintNode(l1);
  return {node->p1, node->p2, nullptr, nullptr};
}

extern "C" void __polytracker_log_union(const dfsan_label &l1,
                                        const dfsan_label &l2,
                                        const dfsan_label &union_label) {
  // Note (Carson), we don't really have control over decay anymore.
  // if (LIKELY(!done)) {
  logUnion(l1, l2, union_label, 100);
  // }
}

extern "C" int __polytracker_size() { return function_stack.size(); }

extern "C" void __polytracker_start(func_mapping const* globals, uint64_t globals_count,
                       block_mapping const* block_map, uint64_t block_map_count) {
  polytracker_start(globals, globals_count, block_map, block_map_count); 
}

extern "C" void
__polytracker_store_function_mapping(const func_mapping *func_map,
                                     uint64_t *count) {
  func_mappings = func_map;
  func_mapping_count = *count;
}

extern "C" void
__polytracker_store_block_mapping(const block_mapping *block_map,
                                  uint64_t *count) {
  block_mappings = block_map;
  block_mapping_count = *count;
}

extern "C" void __polytracker_store_blob(char **argv) {
  const char *current_prog = argv[0];
  char *data;
  FILE *prog_fd = fopen(current_prog, "rb");
  fseek(prog_fd, 0, SEEK_END);
  int size = ftell(prog_fd);
  fseek(prog_fd, 0, SEEK_SET);
  data = (char *)malloc(sizeof(*data) * size);
  fread(data, 1, size, prog_fd);
  storeBlob(output_db, data, size);
  free(data);
}

extern "C" void dfs$__polytracker_log_call_exit(uint32_t func_index,
                                                uint32_t block_index,
                                                const int stack_loc) {
  fprintf(stdout, "WARNING Using instrumented log call exit func\n");
  __polytracker_log_call_exit(func_index, block_index, stack_loc);
}

// These two dfs$ functions exist for testing
// If polytracker-llvm needs an update but it's too time consuming to
// rebuild/wait
extern "C" void dfs$__polytracker_start(func_mapping const* globals, uint64_t globals_count,
                       block_mapping const* block_map, uint64_t block_map_count) {
  fprintf(stderr, "WARNING Using instrumented internal start func\n");
  __polytracker_start(globals, globals_count, block_map, block_map_count);
}
extern "C" int dfs$__polytracker_size() {
  fprintf(stderr, "WARNING Using instrumented internal size func\n");
  return __polytracker_size();
}

extern "C" void __polytracker_print_label(dfsan_label l1) {
  printf("label from inst is: %" PRIu32 "\n", l1);
}

extern "C" void __polytracker_dump(const dfsan_label last_label) {}

extern "C" int __polytracker_has_label(dfsan_label label, dfsan_label elem) {
  return false;
}