#ifndef GIGAFUNC_TRACELIB_H
#define GIGAFUNC_TRACELIB_H

#include "gigafunction/types.h"

// Interface between instrumented code and librt

extern "C" void gigafunction_enter_block(gigafunction::thread_state_handle, gigafunction::block_id);

extern "C" gigafunction::thread_state_handle gigafunction_get_thread_state();


#endif