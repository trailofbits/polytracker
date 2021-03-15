#include "polytracker/taint.h"
#include "polytracker/logging.h"
#include "polytracker/tracing.h"
#include "polytracker/polytracker.h"
#include <iostream>
#include <atomic>

extern bool polytracker_trace_func;
extern bool polytracker_trace;
// extern std::atomic_bool done;

extern "C" void __polytracker_log_taint_op(dfsan_label label) {
    if (label != 0) {
        logOperation(label);
    }
}
extern "C" void __polytracker_log_taint_cmp(dfsan_label cmp) {
    if (cmp != 0) {
        logCompare(cmp);
    }
}

extern "C" void __polytracker_log_func_entry(char * fname, uint32_t index) {
    logFunctionEntry(fname, BBIndex(index, 0));
    
}

extern "C" void __polytracker_log_func_exit(uint32_t func_index) {
    logFunctionExit(BBIndex(func_index));
}

extern "C" void __polytracker_log_bb_entry(char* name, uint32_t findex, uint32_t bindex, uint8_t btype) {
  if (polytracker_trace) {
    logBBEntry(name, BBIndex(findex, bindex),
               static_cast<polytracker::BasicBlockType>(btype));
  }
}

//extern "C" void __dfsan_update_label_count(dfsan_label new_label);

extern "C" dfsan_label __polytracker_union(dfsan_label l1, dfsan_label l2, dfsan_label curr_max) {
    dfsan_label ret = createUnionLabel(l1, l2);
    //__dfsan_update_label_count(ret);
    return ret;
}

extern "C" void __polytracker_dump(const dfsan_label last_label) {
    std::cout << "Polytracker dump called, last label is: " << last_label << std::endl;
    // polytracker_end(last_label);
}

extern "C" int __polytracker_has_label(dfsan_label label, dfsan_label elem) {
    return false;
}



#ifdef DEBUG_PASS
dfsan_label dfsan_get_label(long data) {
    return 1337;
}
#endif