#ifndef DFSAN_LOG_TAINT
#define DFSAN_LOG_TAINT

#include "../sanitizer_common/sanitizer_atomic.h"
#include "../sanitizer_common/sanitizer_common.h"
#include "../sanitizer_common/sanitizer_file.h"
#include "../sanitizer_common/sanitizer_flags.h"
#include "../sanitizer_common/sanitizer_flag_parser.h"
#include "../sanitizer_common/sanitizer_libc.h"

#include <vector>
#include <string>
#include <unordered_map> 
#include <unordered_set> 
#include <mutex>
#include <iostream> 

#include "lrucache/lrucache.hpp"
#include "dfsan/dfsan.h"
//Amalgamated CRoaring files
#include "polytracker.h"
#include "json.hpp"

using json = nlohmann::json; 

typedef std::unordered_map<std::thread::id, std::vector<std::string>> thread_id_map; 
typedef std::unordered_map<std::string, std::unordered_set<taint_node_t*>> string_node_map; 

/*
 * This manages the mapping between taint_label <--> taint_node 
 * NOTE an instance of this class is shared between the log manager and prop manager 
 * It has its own lock to prevent concurency issues 
 */
class taintMappingManager {
	public:
		taintMappingManager(char * shad_mem_ptr, char * taint_forest_ptr);
		~taintMappingManager(); 
		inline taint_node_t * getTaintNode(dfsan_label label); 
		inline dfsan_label getTaintLabel(taint_node_t * node);
	private: 
		std::mutex taint_mapping_lock;
	 	char * shad_mem; 
		char * forest_mem; 	
}; 

/*
 * This class is responsible for converting vectors to output (json or raw) 
 */
class taintOutputManager {
	public:
		taintOutputManager(char * outfile, bool dump_raw_taint_info, taintMappingManager * map_mgr); 
	private:
		std::string outfile; 
		bool dump_raw_taint_info;
	 	json output_json;
		taintMappingManager * map_manager; 	
};

/*
 * This class will create and call methods in taintOutputManager and taintIntervalManager
 */
class taintLogManager {
	public:
		taintLogManager(char * outfile, taintMappingManager * map_mgr); 
		taintLogManager(); 
		~taintLogManager(); 
		void logCompare(dfsan_label some_label); 
		void logOperation(dfsan_label some_label);
		void logFunctionEntry(std::string fname); 
		void logFunctionExit();
	private:
		thread_id_map thread_stack_map; 
		string_node_map function_to_bytes;
	 	string_node_map function_to_cmp_bytes;
		std::unordered_map<std::string, std::unordered_set<std::string>> runtime_cfg;
		std::mutex taint_log_lock;
		taintOutputManager * output_manager; 
};

/*
 * Create labels and union labels together 
 */
class taintPropagationManager {
	public: 
		taintPropagationManager(taintMappingManager * map_mgr, decay_val init_decay_val, dfsan_label start_union_label); 
		~taintPropagationManager();
	 	dfsan_label createNewLabel(dfsan_label offset, taint_source_id taint_id); 
	 	dfsan_label unionLabels(dfsan_label l1, dfsan_label l2); 	
	private:
		void _checkMaxLabel(dfsan_label label); 
		dfsan_label _createUnionLabel(dfsan_label l1, dfsan_label l2, decay_val init_decay);
	 	//This is a data structures that helps prevents repeat pairs of bytes from generating new labels.
		//The original in DFsan was a matrix that was pretty sparse, so this saves space and also helps
		//While its not a full solution, it actually reduces the amount of labels by a lot, so its worth having
		std::unordered_map<dfsan_label, std::unordered_map<dfsan_label, dfsan_label>> union_table; 	
		decay_val taint_node_ttl;
		std::mutex taint_prop_lock;
	  //Using atomic store and load to access this, so if we change our locking later its still fine	
		atomic_dfsan_label next_union_label; 	
		taintMappingManager * map_manager; 
};

#endif 

