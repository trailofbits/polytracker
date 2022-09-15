#include "polytracker/polytracker.h"
#include "polytracker/early_construct.h"
#include "taintdag/fnmapping.h"
#include "polytracker/taint_sources.h"
#include "taintdag/polytracker.h"
#include <atomic>
#include <inttypes.h>
#include <iostream>
#include <sanitizer/dfsan_interface.h>

extern bool polytracker_trace_func;
extern bool polytracker_trace;

const func_mapping *func_mappings;
uint64_t func_mapping_count;

const block_mapping *block_mappings;
uint64_t block_mapping_count;

EARLY_CONSTRUCT_EXTERN_GETTER(taintdag::PolyTracker, polytracker_tdag);

extern "C" void __polytracker_log_taint_op(dfsan_label arg1, dfsan_label arg2,
                                           uint32_t findex, uint32_t bindex) {}

extern "C" void __dfsw___polytracker_log_taint_op(
    uint32_t arg1, uint32_t arg2, uint32_t findex, uint32_t bindex,
    dfsan_label arg1_label, dfsan_label arg2_label, dfsan_label ignore_label1,
    dfsan_label ignore_label2) {}

extern "C" void __polytracker_log_taint_cmp(dfsan_label arg1, dfsan_label arg2,
                                            uint32_t findex, uint32_t bindex) {}

extern "C" void __dfsw___polytracker_log_taint_cmp(
    uint64_t arg1, uint64_t arg2, uint32_t findex, uint32_t bindex,
    dfsan_label arg1_label, dfsan_label arg2_label, dfsan_label ignore_label1,
    dfsan_label ignore_label2) {}

// extern "C" int __polytracker_log_func_entry(uint32_t index) { return 0; }

extern "C" taintdag::FnMapping::index_t
__polytracker_log_func_entry(char *name) {
  return get_polytracker_tdag().function_entry(name);
}

// extern "C" void __polytracker_log_func_exit(uint32_t func_index,
//                                             uint32_t block_index,
//                                             const int stack_loc) {}

extern "C" void __polytracker_log_func_exit(uint16_t func_index) {
  get_polytracker_tdag().function_exit(func_index);
}

extern "C" void __polytracker_log_call_exit(uint32_t func_index,
                                            uint32_t block_index,
                                            const int stack_loc) {}

extern "C" void __polytracker_log_call_uninst(uint32_t func_index,
                                              uint32_t block_index,
                                              char *fname) {}

extern "C" void __polytracker_log_call_indirect(uint32_t func_index,
                                                uint32_t block_index) {}

extern "C" void __polytracker_log_bb_entry(uint32_t findex, uint32_t bindex,
                                           uint8_t btype) {}

extern "C" dfsan_label __polytracker_union_table(const dfsan_label &l1,
                                                 const dfsan_label &l2) {
  return get_polytracker_tdag().union_labels(l1, l2);
}

extern "C" void __polytracker_preserve_map(char *map) {}

extern "C" void __polytracker_log_conditional_branch(dfsan_label label) {
  if (label > 0) {
    get_polytracker_tdag().affects_control_flow(label);
  }
}

extern "C" void
__dfsw___polytracker_log_conditional_branch(uint64_t conditional,
                                            dfsan_label conditional_label) {
  __polytracker_log_conditional_branch(conditional_label);
}

extern "C" void __polytracker_log_union(const dfsan_label &l1,
                                        const dfsan_label &l2,
                                        const dfsan_label &union_label) {}

extern "C" int __polytracker_size() { return 0; }

extern "C" void __polytracker_start(func_mapping const *globals,
                                    uint64_t globals_count,
                                    block_mapping const *block_map,
                                    uint64_t block_map_count,
                                    bool no_control_flow_tracing) {
  polytracker_start(globals, globals_count, block_map, block_map_count,
                    no_control_flow_tracing);
}

extern "C" void __taint_start() { taint_start(); }

extern "C" void __polytracker_taint_argv(int argc, char *argv[]) {
  polytracker::taint_argv(argc, argv);
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

extern "C" void dfs$__polytracker_log_call_exit(uint32_t func_index,
                                                uint32_t block_index,
                                                const int stack_loc) {
  fprintf(stdout, "WARNING Using instrumented log call exit func\n");
}

// These two dfs$ functions exist for testing
// If polytracker-llvm needs an update but it's too time consuming to
// rebuild/wait
extern "C" void dfs$__polytracker_start(func_mapping const *globals,
                                        uint64_t globals_count,
                                        block_mapping const *block_map,
                                        uint64_t block_map_count,
                                        bool control_flow_tracking) {
  fprintf(stderr, "WARNING Using instrumented internal start func\n");
}

extern "C" void dfs$__taint_start() {
  fprintf(stderr, "WARNING Using instrumented internal start func\n");
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