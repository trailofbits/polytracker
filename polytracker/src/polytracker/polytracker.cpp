#include "polytracker/polytracker.h"
#include "polytracker/early_construct.h"
#include "polytracker/taint_sources.h"
#include "taintdag/fnmapping.h"
#include "taintdag/polytracker.h"
#include <sanitizer/dfsan_interface.h>

#include <atomic>
#include <inttypes.h>
#include <iostream>

EARLY_CONSTRUCT_EXTERN_GETTER(taintdag::PolyTracker, polytracker_tdag);

static std::atomic_flag polytracker_init_flag = ATOMIC_FLAG_INIT;

static void polytracker_initialize() {
  polytracker_init_flag.test_and_set(std::memory_order_relaxed);
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

extern "C" void __taint_start() {
  taint_start();
  polytracker_initialize();
}

extern "C" void __polytracker_taint_argv(int argc, char *argv[]) {
  polytracker::taint_argv(argc, argv);
}

extern "C" uint64_t __dfsw___polytracker_log_tainted_control_flow(
    uint64_t conditional, uint32_t functionid, dfsan_label conditional_label,
    dfsan_label function_label, dfsan_label *ret_label) {
  if (conditional_label > 0) {
    get_polytracker_tdag().log_tainted_control_flow(conditional_label,
                                                    functionid);
  }

  *ret_label = conditional_label;
  return conditional;
}

extern "C" void __polytracker_enter_function(uint32_t function_id, const char* function_name) {
  get_polytracker_tdag().enter_function(function_id);
  get_polytracker_tdag().record_function_name(function_id, std::string_view(function_name));
}

extern "C" void __polytracker_leave_function(uint32_t function_id) {
  get_polytracker_tdag().leave_function(function_id);
}