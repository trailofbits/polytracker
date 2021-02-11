#ifndef DFSAN_TYPES_H
#define DFSAN_TYPES_H
//#include "sanitizer_common/sanitizer_atomic.h"
//#include "sanitizer_common/sanitizer_internal_defs.h"
#include <functional>
#include <stdint.h>

//using __sanitizer::u16;
//using __sanitizer::u32;
//using __sanitizer::uptr;
//using namespace __dfsan;
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
typedef PPCAT(PPCAT(uint, DFSAN_LABEL_BITS), _t) dfsan_label;

// An unsigned int big enough to address a dfsan label:
typedef PPCAT(PPCAT(uint, DFSAN_LABEL_BITS), _t) uint_dfsan_label_t;

// FIXME Should this be a uint8_t or uint16_t? 
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

class BBIndex {
  // Most significant 32 bits are the UID for the function containing this BB
  // Least significant 32 bits are the index of this BB within the function
  // Taken together as a 64bit value, this entails a unique ID for this BB
  uint64_t value;

public:
  constexpr BBIndex() : value(0) {}
  constexpr BBIndex(uint32_t functionIndex, uint32_t indexInFunction)
      : value((static_cast<uint64_t>(functionIndex) << 32) | indexInFunction) {}
  constexpr BBIndex(uint64_t uid) : value(uid) {}
  constexpr BBIndex(const BBIndex &copy) : value(copy.value){};

  constexpr operator bool() const noexcept { return value != 0; }

  constexpr operator uint64_t() const noexcept { return value; }

  constexpr uint64_t uid() const noexcept { return value; }

  /**
   * Returns a unique ID for the function containing this BB
   */
  constexpr uint32_t functionIndex() const noexcept { return value >> 32; }

  /**
   * Returns the index of this basic block within its function
   */
  constexpr uint32_t index() const noexcept { return value & 0xFFFFFFFF; }

  constexpr bool operator==(const BBIndex other) const noexcept {
    return value == other.value;
  }

  constexpr bool operator<(const BBIndex other) const noexcept {
    return value < other.value;
  }
};

namespace std {

template <> struct hash<BBIndex> {
  constexpr std::size_t operator()(const BBIndex &i) const { return i.uid(); }
};

} // namespace std

#endif
