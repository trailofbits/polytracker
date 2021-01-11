#include "polytracker/taint.h"
#include "polytracker/logging.h"


extern "C" void __polytracker_log_taint_op(dfsan_label label) {

}
extern "C" void __polytracker_log_taint_cmp(dfsan_label cmp) {

}
//TODO This is wrong, we should merge with the sqlite stuff and pull how they do 
extern "C" void __polytracker_log_func_entry(char * fname, dfsan_label something) {

}

extern "C" void __polytracker_log_func_exit(dfsan_label idk) {

}

extern "C" void __polytracker_log_bb_entry(char* name, uint32_t findex, uint32_t bindex, uint8_t*idk) {

}



#define DEBUG_PASS
#ifdef DEBUG_PASS
dfsan_label dfsan_get_label(long data) {
    return 1337;
}
#endif