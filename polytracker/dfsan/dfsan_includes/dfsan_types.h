#ifndef DFSAN_TYPES_H
#define DFSAN_TYPES_H
#include "dfsan_rt/sanitizer_common/sanitizer_internal_defs.h" 
#include <stdint.h> 

using __sanitizer::uptr;
using __sanitizer::u16;
using __sanitizer::u32;

/* This defines how many bits are used for dfsan labels.
 * It automatically influences the types of `dfsan_label`,
 * `atomic_dfsan_label`, `uint_dfsan_label_t`, as well as
 * the calculation of `MAX_LABELS`.
 */
#define DFSAN_LABEL_BITS 32

#define PPCAT_NX(A, B) A ## B
#define PPCAT(A, B) PPCAT_NX(A, B)

// Copy declarations from public sanitizer/dfsan_interface.h header here.
typedef PPCAT(u, DFSAN_LABEL_BITS) dfsan_label;

typedef uint32_t decay_val;
#undef PPCAT_NX
#undef PPCAT

typedef struct taint_node {
 //Pointers for parent nodes
 struct taint_node * p1;
 struct taint_node * p2;
 //Bit field for special features about the label, like is it len_label.
 char bit_field;
 //Decay field
 decay_val decay;
} taint_node_t;

#endif
