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
#include "../sanitizer_common/sanitizer_atomic.h"
#include "../sanitizer_common/sanitizer_common.h"
#include "../sanitizer_common/sanitizer_file.h"
#include "../sanitizer_common/sanitizer_flags.h"
#include "../sanitizer_common/sanitizer_flag_parser.h"
#include "../sanitizer_common/sanitizer_libc.h"
#include "polytracker.h" 
#include "dfsan_log_mgmt.h" 

#include <vector> 
#include <string> 
#include <string.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <unordered_set>
#include <set>
#include <algorithm>
#include <stack> 
#include <thread> 
#include "dfsan/dfsan.h"
#include <stdint.h> 
#include <mutex> 
//Only include this in here, headers are shared via dfsan.h
#include "roaring.c" 
using json = nlohmann::json;
using namespace __dfsan;

//This keeps track of the current taint label we are on 
static atomic_dfsan_label __dfsan_last_label;

Flags __dfsan::flags_data;
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL dfsan_label __dfsan_retval_tls;
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL dfsan_label __dfsan_arg_tls[64];
SANITIZER_INTERFACE_ATTRIBUTE uptr __dfsan_shadow_ptr_mask;

//This is a boundry we use when setting up the address space
static uptr forest_base_addr = MappingArchImpl<MAPPING_TAINT_FOREST_ADDR>();

//These are some configuration options set via some enviornment variables to change resource usage 
//And tracking behavior dump_forest dumps shadow memory content and function_to_bytes map, see above 
static bool dump_forest_and_sets = false;

//This is a decay value, its a practical choice made due to the inherent problems when using taint analysis 
//Specifically, when analyzing functions that manipulate a lot of data, like decompression functions, youll get way too much data 
//This "decay" value is similar to hop count in packets, the higher this value, the longer your taint will live. 
//The algorithm used models exponential decay, please check out the creation of union labels for more info 
static decay_val taint_node_ttl = DEFAULT_TTL;

//During processing we have an LRU cache which allows us to memoize some results 
//This can use up a lot of memory so we have a setting for the cache size 
static uint64_t dfs_cache_size = DEFAULT_CACHE;

//This is the output file name
static const char * polytracker_output_json_filename;

//Used by taint sources
taintInfoManager * taint_info_manager;

//This is left here because its shared by prop_mgr and log_mgr 
//Should be deleted after both of them, should not be used directly!    
taintMappingManager * taint_map_mgr; 
taintPropagationManager * taint_prop_manager; 
taintLogManager * taint_log_manager; 

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
	//The unused region 
	return MappingArchImpl<MAPPING_TAINT_FOREST_ADDR>() + (sizeof(taint_node_t) * MAX_LABELS);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_reset_frame(int* index) {
	taint_log_manager->resetFrame(index);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
int __dfsan_func_entry(char * fname) {
	init_lock.lock(); 
	if (is_init == false) {
		dfsan_late_init();
		is_init = true; 	
	}
	init_lock.unlock(); 
	return taint_log_manager->logFunctionEntry(fname);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_log_taint_cmp(dfsan_label some_label) {
	taint_log_manager->logCompare(some_label); 
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_log_taint(dfsan_label some_label) {
	taint_log_manager->logOperation(some_label); 
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_func_exit() {
	taint_log_manager->logFunctionExit(); 
}

// Resolves the union of two unequal labels.  Nonequality is a precondition for
// this function (the instrumentation pass inlines the equality test).
// The union table prevents there from being dupilcate labels
// This dfs_lookup_cache is to make it so we dont have to do traverals a lot.
// This assumes that a lot of taint will be generated in functions and not used again
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __dfsan_union(dfsan_label l1, dfsan_label l2) {
	return taint_prop_manager->unionLabels(l1, l2);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __dfsan_union_load(const dfsan_label *ls, uptr n) {
	dfsan_label label = ls[0];
	for (uptr i = 1; i != n; ++i) {
		dfsan_label next_label = ls[i];
		if (label != next_label)
			label = __dfsan_union(label, next_label);
	}
	return label;
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_unimplemented(char *fname) {
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
extern "C" SANITIZER_INTERFACE_ATTRIBUTE void
__dfsan_vararg_wrapper(const char *fname) {
	Report("FATAL: DataFlowSanitizer: unsupported indirect call to vararg "
			"function %s\n", fname);
	Die();
}

// Like __dfsan_union, but for use from the client or custom functions.  Hence
// the equality comparison is done here before calling __dfsan_union.
SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_union(dfsan_label l1, dfsan_label l2) {
	if (l1 == l2)
		return l1;
	return __dfsan_union(l1, l2);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label dfsan_create_label(uint_dfsan_label_t offset, taint_source_id taint_id) {
	return taint_prop_manager->createNewLabel(offset, taint_id);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_set_label(dfsan_label label, void *addr, uptr size) {
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
extern "C" SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
__dfsw_dfsan_get_label(long data, dfsan_label data_label,
		dfsan_label *ret_label) {
	*ret_label = 0;
	return data_label;
}

SANITIZER_INTERFACE_ATTRIBUTE dfsan_label
dfsan_read_label(const void *addr, uptr size) {
	if (size == 0)
		return 0;
	return __dfsan_union_load(shadow_for(addr), size);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE uptr
dfsan_get_label_count(void) {
	dfsan_label max_label_allocated =
		atomic_load(&__dfsan_last_label, memory_order_relaxed);

	return static_cast<uptr>(max_label_allocated);
}

void Flags::SetDefaults() {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) Name = DefaultValue;
#include "dfsan_flags.inc"
#undef DFSAN_FLAG
}

static void RegisterDfsanFlags(FlagParser *parser, Flags *f) {
#define DFSAN_FLAG(Type, Name, DefaultValue, Description) \
	RegisterFlag(parser, #Name, Description, &f->Name);
#include "dfsan_flags.inc"
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
	if (Verbosity()) ReportUnrecognizedFlags();
	if (common_flags()->help) parser.PrintFlagDescriptions();
}

static void InitializePlatformEarly() {
	AvoidCVE_2016_2143();
#ifdef DFSAN_RUNTIME_VMA
	__dfsan::vmaSize =
		(MostSignificantSetBitIndex(GET_CURRENT_FRAME()) + 1);
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
#ifdef DEBUG_INFO
	fprintf(stderr, "FINISHED TRACKING, max label %lu, dumping json to %s!\n",
			dfsan_get_label_count(), polytracker_output_json_filename);
	fflush(stderr);
#endif
	dfsan_label max_label = taint_prop_manager->getMaxLabel();
	taint_log_manager->output(max_label); 
	delete taint_info_manager;
	delete taint_map_mgr; 
	delete taint_prop_manager;
	delete taint_log_manager;
}

// This function is like `getenv`.  So why does it exist?  It's because dfsan
// gets initialized before all the internal data structures for `getenv` are
// set up. This is similar to how ASAN does it 
static char * dfsan_getenv(const char * name) {
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
		char* endp =
			(char*)memchr(p, '\0', len - (p - environ));
		if (!endp) { // this entry isn't NUL terminated
			fprintf(stderr, "Something in the env is not null terminated, exiting!\n"); 
			return NULL;
		}
		// match
		else if (!memcmp(p, name, namelen) && p[namelen] == '=')  {
#ifdef DEBUG_INFO
			fprintf(stderr, "Found target file\n");
#endif
			return p + namelen + 1;
		}
		p = endp + 1;
	}
	return NULL;
}

void dfsan_late_init() {
	InitializeFlags();
	InitializePlatformEarly();
	//Note for some reason this original mmap call also mapped in the union table
	//I don't think we need to make any changes to this 
	if (!MmapFixedNoReserve(ShadowAddr(), UnusedAddr() - ShadowAddr()))
		Die();

	// Protect the region of memory we don't use, to preserve the one-to-one
	// mapping from application to shadow memory. But if ASLR is disabled, Linux
	// will load our executable in the middle of our unused region. This mostly
	// works so long as the program doesn't use too much memory. We support this
	// case by disabling memory protection when ASLR is disabled.
	uptr init_addr = (uptr)&dfsan_late_init;
	if (!(init_addr >= UnusedAddr() && init_addr < AppAddr()))
		MmapFixedNoAccess(UnusedAddr(), AppAddr() - UnusedAddr());

	InitializeInterceptors();

	taint_info_manager = new taintInfoManager(); 
	if (taint_info_manager == NULL) {
		fprintf(stderr, "Error! Unable to create taint info manager, dying!\n"); 
		exit(1);
	}
	
	const char * target_file = dfsan_getenv("POLYPATH");
	if (target_file == NULL) {
		fprintf(stderr, "Unable to get required POLYPATH environment variable -- perhaps it's not set?\n");
		exit(1);
	}
	const char * output_file = dfsan_getenv("POLYOUTPUT"); 
	if (output_file == NULL) {
		output_file = "polytracker"; 
	}	
	//Get file size start and end
	FILE * temp_file = fopen(target_file, "r");
	if (temp_file == NULL) {
		fprintf(stderr, "Error: target file \"%s\" could not be opened: %s\n",
				target_file, strerror(errno));
		exit(1);
	}
#ifdef DEBUG_INFO
	fprintf(stderr, "File is %s\n", target_file);
#endif
	fseek(temp_file, 0L, SEEK_END);
	int byte_start = 0;
	uint64_t byte_end = ftell(temp_file);
#ifdef DEBUG_INFO
	fprintf(stderr, "BYTE_END IS: %d\n", byte_end);
#endif	
	fclose(temp_file);
	taint_info_manager->createNewTargetInfo(target_file, byte_start, byte_end); 
	//Special tracking for standard input
	taint_info_manager->createNewTargetInfo("stdin", 0, MAX_LABELS); 
	taint_info_manager->createNewTaintInfo(stdin, "stdin");  
	const char * poly_output = dfsan_getenv("POLYOUTPUT");
	if (poly_output != NULL) {
		polytracker_output_json_filename = poly_output;
	} else {
		polytracker_output_json_filename = "polytracker.json";
	}
	if (dfsan_getenv("POLYDUMP") != NULL) {
		dump_forest_and_sets = true;
	}

	const char * env_ttl = dfsan_getenv("POLYTTL");
	decay_val taint_node_ttl = DEFAULT_TTL; 
	if (env_ttl != NULL) {
		taint_node_ttl = atoi(env_ttl);
#ifdef DEBUG_INFO
		fprintf(stderr, "Taint node TTL is: %d\n", taint_node_ttl);
#endif
	}
	const char * env_cache = dfsan_getenv("POLYCACHE");
	if (env_cache != NULL) {
		dfs_cache_size = atoi(env_cache);
#ifdef DEBUG_INFO
		fprintf(stderr, "DFS cache size: %d\n", dfs_cache_size);
#endif
	}

	/* byte_end + 1 because labels are offset by 1 because the zero label is reserved for
	 * "no label". So, the start of union_labels is at (# bytes in the input file) + 1.
	 */
	atomic_store(&__dfsan_last_label, byte_end + 1, memory_order_release);
	
  taint_map_mgr = new taintMappingManager((char*)ShadowAddr(), (char*)ForestAddr());  
	if (taint_map_mgr == nullptr) {
		fprintf(stderr, "Taint mapping manager null!\n"); 
		exit(1);
	}
	
	taint_prop_manager = new taintPropagationManager(taint_map_mgr, taint_node_ttl, byte_end + 1);	
	if (taint_prop_manager == nullptr) {
		fprintf(stderr, "Taint prop manager null!\n"); 
		exit(1); 
	}

	taint_log_manager = new taintLogManager(taint_map_mgr, taint_info_manager,
		 	polytracker_output_json_filename, dump_forest_and_sets, dfs_cache_size); 
	if (taint_log_manager == nullptr) {
		fprintf(stderr, "Taint log manager is null!\n"); 
		exit(1);
	}	
	// Register the fini callback to run when the program terminates
	// successfully or it is killed by the runtime.
	//
	// Note: we do this at the very end of initialization, so that if
	// initialization itself fails for some reason, we don't try to call
	// `dfsan_fini` from a partially-initialized state.
	Atexit(dfsan_fini);
	AddDieCallback(dfsan_fini);

#ifdef DEBUG_INFO
	fprintf(stderr, "Done init\n");
#endif
}
