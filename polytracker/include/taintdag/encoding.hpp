#ifndef POLYTRACKER_TAINTDAG_ENCODING_H
#define POLYTRACKER_TAINTDAG_ENCODING_H
#include "taintdag/taint.hpp"

namespace taintdag {

// Encodes a Taint value into its encoded version. Please see source file for details.
storage_t encode(Taint const &taint);

// Decodes encoded value into Taint. If encoded is not 'valid' the process will exit with error.
Taint decode(storage_t encoded);

// True is encoded value is source taint
bool is_source_taint(storage_t encoded);

// Add the affects control flow flag to an encoded taint value
storage_t add_affects_control_flow(storage_t encoded);

}

#endif