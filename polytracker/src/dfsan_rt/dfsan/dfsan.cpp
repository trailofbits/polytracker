//===-- dfsan.cc ----------------------------------------------------------===//
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
// DataFlowSanitizer runtime.  This file defines the public interface to
// DataFlowSanitizer as well as the definition of certain runtime functions
// called automatically by the compiler (specifically the instrumentation pass
// in llvm/lib/Transforms/Instrumentation/DataFlowSanitizer.cpp).
//
// The public interface is defined in include/sanitizer/dfsan_interface.h whose
// functions are prefixed dfsan_ while the compiler interface functions are
// prefixed __dfsan_.
//===----------------------------------------------------------------------===//
#include "dfsan/dfsan.h"

#include "dfsan/dfsan_log_mgmt.h"
#include "polyclang/polytracker.h"
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_libc.h"
// Only include this in here, headers are shared via dfsan.h
#include <stdint.h>
#include <string.h>

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <set>
#include <stack>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#define DEBUG_INFO
#include "dfsan/roaring.c"

using json = nlohmann::json;
using namespace __dfsan;

// This keeps track of the current taint label we are on
// static atomic_dfsan_label __dfsan_last_label;

Flags __dfsan::flags_data;
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL dfsan_label __dfsan_retval_tls;
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL dfsan_label __dfsan_arg_tls[64];
SANITIZER_INTERFACE_ATTRIBUTE uptr __dfsan_shadow_ptr_mask;

// This is a boundary we use when setting up the address space
static uptr forest_base_addr = MappingArchImpl<MAPPING_TAINT_FOREST_ADDR>();

// This is a decay value, its a practical choice made due to the inherent
// problems when using taint analysis Specifically, when analyzing functions
// that manipulate a lot of data, like decompression functions, youll get way
// too much data This "decay" value is similar to hop count in packets, the
// higher this value, the longer your taint will live. The algorithm used models
// exponential decay, please check out the creation of union labels for more
// info
static decay_val taint_node_ttl = DEFAULT_TTL;

// This is the output file name
static const char *polytracker_output_filename;

// Manages taint info/propagation
taintManager *taint_manager = nullptr;
static bool is_init = false;
std::mutex init_lock;

// We only support linux x86_64 now
// On Linux/x86_64, memory is laid out as follows:
//
// +--------------------+ 0x800000000000 (top of memory)
// | application memory |
// +--------------------+ 0x700000008000 (kAppAddr)
// |                    |
// |       unused       |
// |                    |
// +--------------------+ 0x40087fffffde (kUnusedAddr)
// |   taint forest     |
// +--------------------+ 0x400000000000 (kTaintForestAddr)
// |   shadow memory    |
// +--------------------+ 0x000000010000 (kShadowAddr)
// | reserved by kernel |
// +--------------------+ 0x000000000000
//
// To derive a shadow memory address from an application memory address,
// bits 44-46 are cleared to bring the address into the range
// [0x000000008000,0x100000000000).  Then the address is shifted left by 1 to
// account for the double byte representation of shadow labels and move the
// address into the shadow memory range.  See the function shadow_for below.

#ifdef DFSAN_RUNTIME_VMA
// Runtime detected VMA size.
int __dfsan::vmaSize;
#endif

static uptr UnusedAddr() {
  // The unused region
  return MappingArchImpl<MAPPING_TAINT_FOREST_ADDR>() +
         (sizeof(taint_node_t) * MAX_LABELS);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_reset_frame(int *index) {
  taint_manager->resetFrame(index);
}

void dfsan_late_late_init();

extern "C" SANITIZER_INTERFACE_ATTRIBUTE int __dfsan_func_entry(char *fname) {
  /*
	init_lock.lock();
  if (is_init == false) {
    dfsan_late_init();
    is_init = true;
  }
  init_lock.unlock();
  */

	init_lock.lock();
	if (is_init == false) {
		dfsan_late_late_init();
		is_init = true;
	}
	init_lock.unlock();

  return taint_manager->logFunctionEntry(fname);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_log_taint_cmp(
    dfsan_label some_label) {
  taint_manager->logCompare(some_label);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_log_taint(
    dfsan_label some_label) {
  taint_manager->logOperation(some_label);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_func_exit() {
  taint_manager->logFunctionExit();
}

// Resolves the union of two unequal labels.  Nonequality is a precondition for
// this function (the instrumentation pass inlines the equality test).
// The union table prevents there from being dupilcate labels
extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
__dfsan_union(dfsan_label l1, dfsan_label l2) {
  return taint_manager->createUnionLabel(l1, l2);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
__dfsan_union_load(const dfsan_label *ls, uptr n) {
  dfsan_label label = ls[0];
  for (uptr i = 1; i != n; ++i) {
    dfsan_label next_label = ls[i];
    if (label != next_label)
      label = __dfsan_union(label, next_label);
  }
  return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_unimplemented(
    char *fname) {
  if (flags().warn_unimplemented) {
#ifdef DEBUG_INFO
    Report("WARNING: DataFlowSanitizer: call to uninstrumented function %s\n",
           fname);
#endif
  }
}

// Use '-mllvm -dfsan-debug-nonzero-labels' and break on this function
// to try to figure out where labels are being introduced in a nominally
// label-free program.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_nonzero_label() {
  if (flags().warn_nonzero_labels)
    Report("WARNING: DataFlowSanitizer: saw nonzero label\n");
}

// Indirect call to an uninstrumented vararg function. We don't have a way of
// handling these at the moment.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_vararg_wrapper(
    const char *fname) {
  Report(
      "FATAL: DataFlowSanitizer: unsupported indirect call to vararg "
      "function %s\n",
      fname);
  Die();
}

// Like __dfsan_union, but for use from the client or custom functions.  Hence
// the equality comparison is done here before calling __dfsan_union.
SANITIZER_INTERFACE_ATTRIBUTE dfsan_label dfsan_union(dfsan_label l1,
                                                      dfsan_label l2) {
  if (l1 == l2)
    return l1;
  return __dfsan_union(l1, l2);
}

/*
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label dfsan_create_canonical_label(int offset) {
        return taint_prop_manager->createCanonicalLabel(offset);
}
*/

extern "C" SANITIZER_INTERFACE_ATTRIBUTE void __dfsan_set_label(
    dfsan_label label, void *addr, uptr size) {
  for (dfsan_label *labelp = shadow_for(addr); size != 0; --size, ++labelp) {
    // Don't write the label if it is already the value we need it to be.
    // In a program where most addresses are not labeled, it is common that
    // a page of shadow memory is entirely zeroed.  The Linux copy-on-write
    // implementation will share all of the zeroed pages, making a copy of a
    // page when any value is written.  The un-sharing will happen even if
    // the value written does not change the value in memory.  Avoiding the
    // write when both |label| and |*labelp| are zero dramatically reduces
    // the amount of real memory used by large programs.
    if (label == *labelp)
      continue;

    *labelp = label;
  }
}

SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_set_label(dfsan_label label, void *addr, uptr size) {
  __dfsan_set_label(label, addr, size);
}

SANITIZER_INTERFACE_ATTRIBUTE
void dfsan_add_label(dfsan_label label, void *addr, uptr size) {
  for (dfsan_label *labelp = shadow_for(addr); size != 0; --size, ++labelp)
    if (*labelp != label)
      *labelp = __dfsan_union(*labelp, label);
}

// Unlike the other dfsan interface functions the behavior of this function
// depends on the label of one of its arguments.  Hence it is implemented as a
// custom function.
extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label __dfsw_dfsan_get_label(
    long data, dfsan_label data_label, dfsan_label *ret_label) {
  *ret_label = 0;
  return data_label;
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label dfsan_read_label(const void *addr,
                                                           uptr size) {
  if (size == 0)
    return 0;
  return __dfsan_union_load(shadow_for(addr), size);
}

void Flags::SetDefaults() {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "dfsan/dfsan_flags.inc"
#undef DFSAN_FLAG
}

static void RegisterDfsanFlags(FlagParser *parser, Flags *f) {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) \
  RegisterFlag(parser, #Name, Description, &f->Name);
#include "dfsan/dfsan_flags.inc"
#undef DFSAN_FLAG
}

static void InitializeFlags() {
  SetCommonFlagsDefaults();
  flags().SetDefaults();

  FlagParser parser;
  RegisterCommonFlags(&parser);
  RegisterDfsanFlags(&parser, &flags());
  parser.ParseString(GetEnv("DFSAN_OPTIONS"));
  InitializeCommonFlags();
  if (Verbosity())
    ReportUnrecognizedFlags();
  if (common_flags()->help)
    parser.PrintFlagDescriptions();
}

static void InitializePlatformEarly() {
  AvoidCVE_2016_2143();
#ifdef DFSAN_RUNTIME_VMA
  __dfsan::vmaSize = (MostSignificantSetBitIndex(GET_CURRENT_FRAME()) + 1);
  if (__dfsan::vmaSize == 39 || __dfsan::vmaSize == 42 ||
      __dfsan::vmaSize == 48) {
    __dfsan_shadow_ptr_mask = ShadowMask();
  } else {
    Printf("FATAL: DataFlowSanitizer: unsupported VMA range\n");
    Printf("FATAL: Found %d - Supported 39, 42, and 48\n", __dfsan::vmaSize);
    Die();
  }
#endif
}

static void dfsan_fini() {
	if (taint_manager == nullptr) {
		return;
	}
  taint_manager->output();
  delete taint_manager;
}

// This function is like `getenv`.  So why does it exist?  It's because dfsan
// gets initialized before all the internal data structures for `getenv` are
// set up. This is similar to how ASAN does it
static char *dfsan_getenv(const char *name) {
  char *environ;
  uptr len;
  uptr environ_size;
  if (!ReadFileToBuffer("/proc/self/environ", &environ, &environ_size, &len)) {
    return NULL;
  }
  uptr namelen = strlen(name);
  char *p = environ;
  while (*p != '\0') {  // will happen at the \0\0 that terminates the buffer
    // proc file has the format NAME=value\0NAME=value\0NAME=value\0...
    char *endp = (char *)memchr(p, '\0', len - (p - environ));
    if (!endp) {  // this entry isn't NUL terminated
      fprintf(stderr,
              "Something in the env is not null terminated, exiting!\n");
      return NULL;
    }
    // match
    else if (!memcmp(p, name, namelen) && p[namelen] == '=') {
#ifdef DEBUG_INFO
      fprintf(stderr, "Found target file\n");
#endif
      return p + namelen + 1;
    }
    p = endp + 1;
  }
  return NULL;
}

void dfsan_parse_env() {
  // Check for path to input file
  const char *target_file = dfsan_getenv("POLYPATH");
  if (target_file == NULL) {
    fprintf(stderr,
            "Unable to get required POLYPATH environment variable -- perhaps "
            "it's not set?\n");
    exit(1);
  }
  // Check if we have an output file name
  const char *output_file = dfsan_getenv("POLYOUTPUT");
  if (output_file == NULL) {
    output_file = "polytracker";
  }

  FILE *temp_file = fopen(target_file, "r");
  if (temp_file == NULL) {
    fprintf(stderr, "Error: target file \"%s\" could not be opened: %s\n",
            target_file, strerror(errno));
    exit(1);
  }

  uint64_t byte_start = 0, byte_end = 0;
  const char *poly_start = dfsan_getenv("POLYSTART");
  if (poly_start != nullptr) {
    byte_start = atoi(poly_start);
  }

  fseek(temp_file, 0L, SEEK_END);
  byte_end = ftell(temp_file);
  const char *poly_end = dfsan_getenv("POLYEND");
  if (poly_end != nullptr) {
    byte_end = atoi(poly_end);
  }
  fclose(temp_file);

  const char *poly_output = dfsan_getenv("POLYOUTPUT");
  if (poly_output != NULL) {
    polytracker_output_filename = poly_output;
  } else {
    polytracker_output_filename = "polytracker";
  }

  taint_manager->setOutputFilename(std::string(polytracker_output_filename));

  const char *env_ttl = dfsan_getenv("POLYTTL");
  decay_val taint_node_ttl = DEFAULT_TTL;
  if (env_ttl != NULL) {
    taint_node_ttl = atoi(env_ttl);
  }

  taint_manager->createNewTargetInfo(target_file, byte_start, byte_end);
  // Special tracking for standard input
  taint_manager->createNewTargetInfo("stdin", 0, MAX_LABELS);
  taint_manager->createNewTaintInfo("stdin", stdin);
}
void dfsan_late_late_init() {
	fprintf(stderr, "LATE LATE INIT");
	  taint_manager = new taintManager(taint_node_ttl, (char *)ShadowAddr(),
	                                   (char *)ForestAddr());
	  if (taint_manager == nullptr) {
	    fprintf(stderr, "Taint prop manager null!\n");
	    exit(1);
	  }
	  dfsan_parse_env();
}
void dfsan_late_init() {
	fprintf(stderr, "TRYING TO INIT\n");
  InitializeFlags();
  InitializePlatformEarly();

  if (!MmapFixedNoReserve(ShadowAddr(), UnusedAddr() - ShadowAddr())) {
    Die();
  }
  fprintf(stderr, "MAPPED MEM\n");
  // Protect the region of memory we don't use, to preserve the one-to-one
  // mapping from application to shadow memory. But if ASLR is disabled, Linux
  // will load our executable in the middle of our unused region. This mostly
  // works so long as the program doesn't use too much memory. We support this
  // case by disabling memory protection when ASLR is disabled.
  uptr init_addr = (uptr)&dfsan_late_init;
  if (!(init_addr >= UnusedAddr() && init_addr < AppAddr())) {
    MmapFixedNoAccess(UnusedAddr(), AppAddr() - UnusedAddr());
  }

  InitializeInterceptors();
  // Register the fini callback to run when the program terminates
  // successfully or it is killed by the runtime.
  //
  // Note: we do this at the very end of initialization, so that if
  // initialization itself fails for some reason, we don't try to call
  // `dfsan_fini` from a partially-initialized state.
  Atexit(dfsan_fini);
  AddDieCallback(dfsan_fini);

#ifdef DEBUG_INFO
  fprintf(stderr, "INIT DONE\n");
#endif
}

__attribute__((section(".preinit_array"),
		used)) static void (*dfsan_init_ptr)() = dfsan_late_init;
