#ifndef DFSAN_TYPES_H
#define DFSAN_TYPES_H
#include <functional>
#include <stdint.h>

/* This defines how many bits are used for dfsan labels.
 * It automatically influences the types of `dfsan_label`,
 * `atomic_dfsan_label`, `uint_dfsan_label_t`, as well as
 * the calculation of `MAX_LABELS`.
 */
#define DFSAN_LABEL_BITS 32
// MAX_LABELS = (2^DFSAN_LABEL_BITS) / 2 - 2 = (1 << (DFSAN_LABEL_BITS - 1)) - 2
// = 2^31 - 2 = 0x7FFFFFFE
#define MAX_LABELS 0xfffffffe

#define PPCAT_NX(A, B) A##B
#define PPCAT(A, B) PPCAT_NX(A, B)

// Copy declarations from public sanitizer/dfsan_interface.h header here.
typedef PPCAT(PPCAT(uint, DFSAN_LABEL_BITS), _t) dfsan_label;

// An unsigned int big enough to address a dfsan label:
typedef PPCAT(PPCAT(uint, DFSAN_LABEL_BITS), _t) uint_dfsan_label_t;

typedef uint8_t decay_val;
#undef PPCAT_NX
#undef PPCAT

typedef struct taint_node {
  dfsan_label p1;
  dfsan_label p2;
  // Decay field
  decay_val decay;
} taint_node_t;

#endif
