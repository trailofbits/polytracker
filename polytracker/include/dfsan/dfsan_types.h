#ifndef DFSAN_TYPES_H
#define DFSAN_TYPES_H
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include <stdint.h>

using __sanitizer::u16;
using __sanitizer::u32;
using __sanitizer::uptr;
using namespace __dfsan;
/* This defines how many bits are used for dfsan labels.
 * It automatically influences the types of `dfsan_label`,
 * `atomic_dfsan_label`, `uint_dfsan_label_t`, as well as
 * the calculation of `MAX_LABELS`.
 */
#define DFSAN_LABEL_BITS 32
#define DFSAN_MAX_TAINT_ID 128
// MAX_LABELS = (2^DFSAN_LABEL_BITS) / 2 - 2 = (1 << (DFSAN_LABEL_BITS - 1)) - 2
// = 2^31 - 2 = 0x7FFFFFFE
#define MAX_LABELS ((1L << (DFSAN_LABEL_BITS - 1)) - 2)

#define PPCAT_NX(A, B) A##B
#define PPCAT(A, B) PPCAT_NX(A, B)

// Copy declarations from public sanitizer/dfsan_interface.h header here.
typedef PPCAT(u, DFSAN_LABEL_BITS) dfsan_label;

typedef PPCAT(PPCAT(atomic_uint, DFSAN_LABEL_BITS), _t) atomic_dfsan_label;
// An unsigned int big enough to address a dfsan label:
typedef PPCAT(PPCAT(uint, DFSAN_LABEL_BITS), _t) uint_dfsan_label_t;

typedef uint32_t decay_val;
#undef PPCAT_NX
#undef PPCAT

typedef struct taint_node {
  // Pointers for parent nodes
  struct taint_node *p1;
  struct taint_node *p2;
  // Decay field
  decay_val decay;
} taint_node_t;

typedef uint64_t BBIndex;

#endif
