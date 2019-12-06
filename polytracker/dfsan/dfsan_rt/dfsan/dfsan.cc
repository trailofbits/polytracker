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

#include <vector> 
#include <string> 
#include <string.h>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <iomanip>
#include <unordered_map>
#include <unordered_set>
#include <set>
#include <unordered_set>
#include <algorithm>
#include <stack> 
#include <nlohmann/json.hpp>
#include <lrucache/lrucache.hpp>
#include "dfsan/dfsan.h"
#include <stdint.h> 
#include <mutex> 
#include <ctime>
//Amalgamated CRoaring lib
#include "roaring.hh"
#include "roaring.c" 
#define MAX_CACHE 100000

// MAX_LABELS = (2^DFSAN_LABEL_BITS) / 2 - 2 = (1 << (DFSAN_LABEL_BITS - 1)) - 2 = 2^31 - 2 = 0x7FFFFFFE
#define MAX_LABELS ((1L << (DFSAN_LABEL_BITS - 1)) - 2)

using json = nlohmann::json;
using namespace __dfsan;

#define PPCAT_NX(A, B) A ## B
#define PPCAT(A, B) PPCAT_NX(A, B)

typedef PPCAT(PPCAT(atomic_uint, DFSAN_LABEL_BITS), _t) atomic_dfsan_label;
// An unsigned int big enough to address a dfsan label:
typedef PPCAT(PPCAT(uint, DFSAN_LABEL_BITS), _t) uint_dfsan_label_t;
static const dfsan_label kInitializingLabel = MAX_LABELS + 1;
static atomic_dfsan_label __dfsan_last_label;
Flags __dfsan::flags_data;
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL dfsan_label __dfsan_retval_tls;
SANITIZER_INTERFACE_ATTRIBUTE THREADLOCAL dfsan_label __dfsan_arg_tls[64];
SANITIZER_INTERFACE_ATTRIBUTE uptr __dfsan_shadow_ptr_mask;
thread_local std::vector<std::string> func_stack;
static uptr forest_base_addr = MappingArchImpl<MAPPING_TAINT_FOREST_ADDR>();
static std::unordered_map<std::string, std::unordered_set<taint_node_t*>> *function_to_bytes;
static std::unordered_map<dfsan_label, std::unordered_map<dfsan_label, dfsan_label>> union_table;
static std::mutex function_to_bytes_mutex;
static std::mutex union_table_mutex;

static bool dump_forest_and_sets = false;
static decay_val taint_node_ttl = 16;
static uint64_t dfs_cache_size = 100000;

static const char *polytracker_output_json_filename;

/*
 * Time info for periodic logging 
 * Interval time = 0 means do nothing 
 */
static double interval_time = 0; //default is 0, do nothing
static clock_t prev_time = 0; 
static clock_t curr_time = 0;

/* Note: the following 3 variables are explicitly non-static */
const char * target_file;
uint_dfsan_label_t byte_start = 0;
uint_dfsan_label_t byte_end;

static void dfsan_create_function_sets(
		json * output_json, std::string fname, 
		std::unordered_set<taint_node_t*> nodes, 
		cache::lru_cache<taint_node_t*, 
		Roaring> * dfs_cache);
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

static inline taint_node_t * node_for(dfsan_label label) {
	//fprintf(stderr, "getting node for\n");
	return (taint_node_t*)(forest_base_addr + (label * sizeof(taint_node_t)));
}
static inline dfsan_label value_for_node(taint_node_t * node) {
	//fprintf(stderr, "getting value forr\n");
	return ((((uptr)node) - forest_base_addr)/sizeof(taint_node_t));
}

// Checks we do not run out of labels.
static void dfsan_check_label(dfsan_label label) {
	if (label == MAX_LABELS) {
		Report("FATAL: DataFlowSanitizer: out of labels\n");
		Die();
	}
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_reset_frame(int* index) {
	func_stack.resize(*index + 1);
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
int __dfsan_func_entry(char * fname) {
#ifdef DEBUG_INFO
	fprintf(stderr, "PUSHING BACK %s\n", fname);
#endif
	func_stack.push_back(fname);
	int ret_val = func_stack.size()-1;
	return ret_val;
}
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_log_taint(dfsan_label some_label) {
	static unsigned int interval_nonce = 0;
	
	//If there is no taint, dont log
	if (some_label == 0) {return;}

	taint_node_t * new_node = node_for(some_label);
	function_to_bytes_mutex.lock();
	(*function_to_bytes)[func_stack[func_stack.size()-1]].insert(new_node);
	
	//If we have an interval timer, check if we should dump to json
	if (interval_time > 0) {
		curr_time = clock();
		double passed_time = double(curr_time - prev_time) / CLOCKS_PER_SEC; 
		if (passed_time > interval_time) {
			json output_json;
			std::unordered_map<std::string, std::unordered_set<taint_node_t*>>::iterator it;
			cache::lru_cache<taint_node_t*, Roaring> * dfs_cache = new cache::lru_cache<taint_node_t*, Roaring>(dfs_cache_size);
			for (it = (*function_to_bytes).begin(); it != (*function_to_bytes).end(); it++) {
				dfsan_create_function_sets(&output_json, it->first, it->second, dfs_cache);
				//Clear vector so future results show new data only
				it->second.clear();
			}

			std::string output_string = "polytracker_interval:" + std::to_string(interval_nonce) + ".json";
			interval_nonce += 1; 
			std::ofstream o(output_string);
			o << std::setw(4) << output_json << std::endl;
			o.close();
		
			delete dfs_cache;
			prev_time = curr_time;
		}
	}	
	function_to_bytes_mutex.unlock();
}

extern "C" SANITIZER_INTERFACE_ATTRIBUTE
void __dfsan_func_exit() {
	func_stack.pop_back();
}

static dfsan_label dfsan_create_union_label(dfsan_label l1, dfsan_label l2, decay_val max_decay) {
	//Fetch new label 
	dfsan_label label = atomic_fetch_add(&__dfsan_last_label, 1, memory_order_relaxed);
	//Check to make sure there is no overflow
	dfsan_check_label(label);
	label++;

	//Grab the pre reserved mem for this region and set vals
	taint_node_t * new_node = node_for(label); 
	new_node->p1 = node_for(l1);
	new_node->p2 = node_for(l2);

	new_node->decay = max_decay;
	new_node->bit_field = '\0';

	return label;
}


// Resolves the union of two unequal labels.  Nonequality is a precondition for
// this function (the instrumentation pass inlines the equality test).
// The union table prevents there from being dupilcate labels
// This dfs_lookup_cache is to make it so we dont have to do traverals a lot.
// This assumes that a lot of taint will be generated in functions and not used again
extern "C" SANITIZER_INTERFACE_ATTRIBUTE
dfsan_label __dfsan_union(dfsan_label l1, dfsan_label l2) {
	DCHECK_NE(l1, l2);
	if (l1 == 0)
		return l2;
	if (l2 == 0)
		return l1;
	if (l1 > l2)
		Swap(l1, l2);

	//Quick union table check 
	if ((union_table[l1]).find(l2) != (union_table[l1]).end()) {
		auto val = union_table[l1].find(l2); 
		return val->second;
	} 
	//Check for max decay
	taint_node_t * p1 = node_for(l1);
	taint_node_t * p2 = node_for(l2);
	//This calculates the average of the two decays, and then decreases it by a factor of 2.
	decay_val max_decay = (p1->decay + p2->decay) / 4;
	if (max_decay == 0) {
		return 0;
	}

	dfsan_label label = dfsan_create_union_label(l1, l2, max_decay);

	union_table_mutex.lock();
	(union_table[l1])[l2] = label;
	union_table_mutex.unlock();
	return label;
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
	if (flags().warn_unimplemented)
		Report("WARNING: DataFlowSanitizer: call to uninstrumented function %s\n",
				fname);
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
dfsan_label dfsan_create_label(uint_dfsan_label_t offset) {
	//File bytes have a mapping to og labels + 1
	dfsan_label label = offset + 1;
	//Grab the pre reserved mem for this region and set vals
	taint_node_t * new_node = node_for(label);
	//Both NULL means canonical parent 
	new_node->p1 = NULL;
	new_node->p2 = NULL;
	new_node->bit_field = '\0';
	new_node->decay = taint_node_ttl;
	return label;
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

static Roaring dfsan_postorder_traversal(taint_node_t * node, 
		cache::lru_cache<taint_node_t*, Roaring> * dfs_cache) {
	//Check cache
	if (dfs_cache->exists(node)) {
		return dfs_cache->get(node);
	}
	Roaring parent_set;
	if (node->p1 == NULL && node->p2 == NULL) {
		parent_set.add(value_for_node(node));
		return parent_set;
	}
	Roaring left_parent_set;
	Roaring right_parent_set; 
	if (node->p1 != NULL) {
		left_parent_set = dfsan_postorder_traversal(node->p1, dfs_cache);
		dfs_cache->put(node->p1, left_parent_set);

	}
	if (node->p2 != NULL) {
		right_parent_set =  dfsan_postorder_traversal(node->p2, dfs_cache);
		dfs_cache->put(node->p1, right_parent_set);
	}
	parent_set = left_parent_set | right_parent_set;
	dfs_cache->put(node, parent_set);
	return parent_set;
}


static void dfsan_create_function_sets(
		json * output_json, 
		std::string fname, 
		std::unordered_set<taint_node_t*> nodes,
		cache::lru_cache<taint_node_t*, Roaring> * dfs_cache) 
{
	Roaring function_set;
	std::unordered_set<taint_node_t*>::iterator it;
#ifdef DEBUG_INFO
	std::cout << "Operating on function " << fname << std::endl;
	std::cout << "Vector size is " << nodes.size() << std::endl;
#endif
	for (it = nodes.begin(); it != nodes.end(); it++) {
		Roaring label_set = dfsan_postorder_traversal(*it, dfs_cache);
		function_set = function_set | label_set;
	}
	//Offset by 1, this orders it for us for output 
	std::set<int> large_set;
	for(Roaring::const_iterator i = function_set.begin(); i != function_set.end(); i++) {
		large_set.insert(*i - 1);
	}
	json j_set(large_set);
	(*output_json)[fname] = j_set; 

}
static void dfsan_dump_forest() {
	std::string forest_fname = std::string(target_file) + "_forest.bin";
	FILE * forest_file = fopen(forest_fname.c_str(), "w");
	if (forest_file == NULL) {
		std::cout << "Failed to dump forest to file: " << forest_fname << std::endl;
		exit(1);
	}
	dfsan_label max_label = dfsan_get_label_count();
	taint_node_t * curr = nullptr;
	for (int i = 0; i < max_label; i++) {
		curr = node_for(i);
		dfsan_label node_p1 = value_for_node(curr->p1);
		dfsan_label node_p2 = value_for_node(curr->p2);
		fwrite(&(node_p1), sizeof(dfsan_label), 1, forest_file);
		fwrite(&(node_p2), sizeof(dfsan_label), 1, forest_file);
		fwrite(&(curr->bit_field), sizeof(curr->bit_field), 1, forest_file);
		fwrite(&(curr->decay), sizeof(curr->decay), 1, forest_file);

	}
	fclose(forest_file);
}

static void dfsan_dump_process_sets() {
	std::unordered_map<std::string, std::unordered_set<taint_node_t*>>::iterator it;
	json output_json;
	for (it = function_to_bytes->begin(); it != function_to_bytes->end(); it++) {
		std::unordered_set<dfsan_label> large_set;
		std::unordered_set<taint_node_t*> ptr_set;
		ptr_set = it->second;
		for (auto ptr_it = ptr_set.begin(); ptr_it != ptr_set.end(); ptr_it++) {
			large_set.insert(value_for_node(*ptr_it));
		}
		json j_set(large_set);
		output_json[it->first] = j_set;
	}
	std::string output_string = std::string(target_file) + "_process_set.json";
	std::ofstream o(output_string);
	o << std::setw(4) << output_json;
	o.close();
}

static void dfsan_fini() {
#ifdef DEBUG_INFO
	fprintf(stderr, "FINISHED TRACKING, max label %lu, dumping json to %s!\n",
			dfsan_get_label_count(), polytracker_output_json_filename);
	fflush(stderr);
#endif

	if (dump_forest_and_sets) {
		dfsan_dump_forest();
		dfsan_dump_process_sets();
	}

	else {
		json output_json;

		std::unordered_map<std::string, std::unordered_set<taint_node_t*>>::iterator it;
		cache::lru_cache<taint_node_t*, Roaring> * dfs_cache = new cache::lru_cache<taint_node_t*, Roaring>(dfs_cache_size);
		for (it = (*function_to_bytes).begin(); it != (*function_to_bytes).end(); it++) {
			dfsan_create_function_sets(&output_json, it->first, it->second, dfs_cache);
		}

		std::ofstream o(polytracker_output_json_filename);
		o << std::setw(4) << output_json << std::endl;
		o.close();

		delete dfs_cache;
	}
	delete function_to_bytes;
}

// This function is an alternative implementation of `getenv`.  So why does it
// exist?  It's because dfsan gets initialized before all the internal data
// structures for `getenv` are set up.
static const char * dfsan_getenv(const char * name) {
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

static void dfsan_init(int argc, char **argv, char **envp) {
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
	uptr init_addr = (uptr)&dfsan_init;
	if (!(init_addr >= UnusedAddr() && init_addr < AppAddr()))
		MmapFixedNoAccess(UnusedAddr(), AppAddr() - UnusedAddr());

	InitializeInterceptors();
	// Register the fini callback to run when the program terminates successfully
	// or it is killed by the runtime.
	Atexit(dfsan_fini);
	AddDieCallback(dfsan_fini);

	//Load environment variables and grab our target file path
	target_file = dfsan_getenv("POLYPATH");
	if (target_file == NULL) {
		fprintf(stderr, "Unable to get required POLYPATH environment variable -- perhaps it's not set?\n");
		exit(1);
	}
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

	const char * env_time_interval = dfsan_getenv("POLYTIME");
	if (env_time_interval != NULL) {
		interval_time = atof(env_time_interval);
#ifdef DEBUG_INFO
		fprintf(stderr, "Time interval in seconds: %d\n", interval_time);
#endif
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
	byte_end = ftell(temp_file);
	fclose(temp_file);

	/* byte_end + 1 because labels are offset by 1 because the zero label is reserved for
	 * "no label". So, the start of union_labels is at (# bytes in the input file) + 1.
	 */
	atomic_store(&__dfsan_last_label, byte_end + 1, memory_order_release);
	function_to_bytes = new std::unordered_map<std::string, std::unordered_set<taint_node_t*>>();
	if (function_to_bytes == NULL) {
		fprintf(stderr, "Failed to allocate function mapping, aborting!\n");
		exit(1);
	}

#ifdef DEBUG_INFO
	fprintf(stderr, "Done init\n");
#endif
}

#if SANITIZER_CAN_USE_PREINIT_ARRAY
__attribute__((section(".preinit_array"), used))
static void (*dfsan_init_ptr)(int, char **, char **) = dfsan_init;
#endif
