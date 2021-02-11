#include "polytracker/taint.h"
#include "polytracker/logging.h"
#include <iostream>

extern "C" void __polytracker_log_taint_op(dfsan_label label) {
    if (label != 0) {
        std::cout << "LOG TAINT OP: " << label << std::endl;
    }

}
extern "C" void __polytracker_log_taint_cmp(dfsan_label cmp) {
    if (cmp != 0) {
        std::cout << "LOG TAINT CMP OP " << cmp << std::endl;
    }
}
//TODO This is wrong, we should merge with the sqlite stuff and pull how they do 
extern "C" void __polytracker_log_func_entry(char * fname, dfsan_label something) {

}

extern "C" void __polytracker_log_func_exit(dfsan_label idk) {

}

extern "C" void __polytracker_log_bb_entry(char* name, uint32_t findex, uint32_t bindex, uint8_t*idk) {

}

extern "C" void __dfsan_update_label_count(dfsan_label new_label);

extern "C" dfsan_label __polytracker_union(dfsan_label l1, dfsan_label l2, dfsan_label curr_max) {
    //TODO Do internal stuff. 
    //TODO Lock?
    __dfsan_update_label_count(curr_max + 1);
    return curr_max + 1;
}

extern "C" void __polytracker_dump(dfsan_label last_label) {
  
}
extern "C" int __polytracker_has_label(dfsan_label label, dfsan_label elem) {
    return false;
}



#ifdef DEBUG_PASS
dfsan_label dfsan_get_label(long data) {
    return 1337;
}
#endif