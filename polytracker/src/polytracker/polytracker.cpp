#include "polytracker/polytracker.h"
#include "polytracker/logging.h"
#include "polytracker/taint.h"
#include <atomic>
#include <iostream>

extern bool polytracker_trace_func;
extern bool polytracker_trace;
extern std::atomic_bool done;

extern "C" void __polytracker_log_taint_op(dfsan_label label, uint32_t findex,
                                           uint32_t bindex) {
  if (label != 0 && (polytracker_trace_func || polytracker_trace) &&
      LIKELY(!done)) {
    logOperation(label, findex, bindex);
  }
}
extern "C" void __polytracker_log_taint_cmp(dfsan_label cmp, uint32_t findex,
                                            uint32_t bindex) {
  if (cmp != 0 && (polytracker_trace_func || polytracker_trace) &&
      LIKELY(!done)) {
    logCompare(cmp, findex, bindex);
  }
}

extern "C" void __polytracker_log_func_entry(char *fname, uint32_t index) {
  if (LIKELY(!done)) {
    logFunctionEntry(fname, index);
  }
}

// TODO (Carson) we can use this block index if we need to.
extern "C" void __polytracker_log_func_exit(uint32_t func_index,
                                            uint32_t block_index) {
  if (LIKELY(!done)) {
    logFunctionExit(func_index);
  }
}

extern "C" void __polytracker_log_bb_entry(char *name, uint32_t findex,
                                           uint32_t bindex, uint8_t btype) {
  if (polytracker_trace && LIKELY(!done)) {
    logBBEntry(name, findex, bindex, btype);
  }
}

// extern "C" void __dfsan_update_label_count(dfsan_label new_label);

extern "C" dfsan_label __polytracker_union(dfsan_label l1, dfsan_label l2,
                                           dfsan_label curr_max) {
  dfsan_label ret = createUnionLabel(l1, l2);
  //__dfsan_update_label_count(ret);
  return ret;
}

extern "C" void __polytracker_dump(const dfsan_label last_label) {}

extern "C" int __polytracker_has_label(dfsan_label label, dfsan_label elem) {
  return false;
}

// This will always get replaced by instrumentation
// It exists here for instrumentation for tests
// Rather than rework our build system, we can have this stub which gets transformed anyway
// extern "C" dfsan_label dfsan_get_label(long data) { return 1337; }