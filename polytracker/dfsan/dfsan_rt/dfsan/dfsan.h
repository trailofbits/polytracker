//===-- dfsan.h -------------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file is a part of DataFlowSanitizer.
//
// Private DFSan header.
//===----------------------------------------------------------------------===//

#ifndef DFSAN_H
#define DFSAN_H
#include "dfsan_types.h"
#include "sanitizer_common/sanitizer_internal_defs.h"
#include "dfsan_platform.h"
#include <stdint.h> 
#include <roaring/roaring.hh>
using __sanitizer::uptr;
using __sanitizer::u16;
using __sanitizer::u32;

extern "C" {
void dfsan_add_label(dfsan_label label, void *addr, uptr size);
void dfsan_set_label(dfsan_label label, void *addr, uptr size);
dfsan_label dfsan_read_label(const void *addr, uptr size);
dfsan_label dfsan_union(dfsan_label l1, dfsan_label l2);
}  // extern "C"

template <typename T>
void dfsan_set_label(dfsan_label label, T &data) {  // NOLINT
  dfsan_set_label(label, (void *)&data, sizeof(T));
}

namespace __dfsan {

void InitializeInterceptors();

inline dfsan_label *shadow_for(void *ptr) {
  return (dfsan_label *) ((((uptr) ptr) & ShadowMask()) << (DFSAN_LABEL_BITS/16));
}

inline const dfsan_label *shadow_for(const void *ptr) {
  return shadow_for(const_cast<void *>(ptr));
}

struct Flags {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) Type Name;
#include "dfsan_flags.inc"
#undef DFSAN_FLAG

  void SetDefaults();
};

extern Flags flags_data;
inline Flags &flags() {
  return flags_data;
}

}  // namespace __dfsan

#endif  // DFSAN_H
