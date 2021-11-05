#ifndef GIGAFUNC_TRACELIB_H
#define GIGAFUNC_TRACELIB_H

#include "gigafunction/types.h"

// Interface between instrumented code and librt

extern "C" void gigafunction_enter_block(gigafunction::thread_state_handle, gigafunction::block_id);

extern "C" gigafunction::thread_state_handle gigafunction_get_thread_state();

// Detoured taint registering functions uses this
namespace gigafunction {

    void env(char const *name, char const *value);


    void openfd(int fd, char const *path = nullptr);
    // NOTE (hbrodin): Currently only recording offset/len 
    // of read data not the actual data.
    void readfd(int fd, size_t pos, size_t len);

    void closefd(int fd);
}

#endif