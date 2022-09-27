#include "polytracker/polytracker.h"
#include "polytracker/early_construct.h"
#include "polytracker/taint_sources.h"
#include "taintdag/fnmapping.h"
#include "taintdag/polytracker.h"
#include <atomic>
#include <inttypes.h>
#include <iostream>
#include <sanitizer/dfsan_interface.h>

EARLY_CONSTRUCT_EXTERN_GETTER(taintdag::PolyTracker, polytracker_tdag);

extern "C" taintdag::FnMapping::index_t
__polytracker_log_func_entry(char *name, uint16_t len) {
  return get_polytracker_tdag().function_entry({name, len});
}

extern "C" void
__polytracker_log_func_exit(taintdag::FnMapping::index_t func_index) {
  get_polytracker_tdag().function_exit(func_index);
}

extern "C" dfsan_label __polytracker_union_table(const dfsan_label &l1,
                                                 const dfsan_label &l2) {
  return get_polytracker_tdag().union_labels(l1, l2);
}

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

extern "C" void __taint_start() { taint_start(); }

extern "C" void __polytracker_taint_argv(int argc, char *argv[]) {
  polytracker::taint_argv(argc, argv);
}