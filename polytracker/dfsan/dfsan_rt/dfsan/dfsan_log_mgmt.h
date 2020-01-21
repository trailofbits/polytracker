#ifndef DFSAN_TAINT_INFO
#define DFSAN_TAINT_INFO

#include <vector>
#include <string>
#include <unordered_map> 
#include <unordered_set> 
#include <mutex>

#include "lrucache/lrucache.hpp"
#include "dfsan/dfsan.h"
//Amalgamated CRoaring files
#include "roaring.hh"
#include "roaring.c"
#include "polytracker.h"
#include "json.hpp"

//FIXME assign actual defaults 
#define DEFAULT_TTL 10
#define DEFAULT_CACHE_SIZE 1000 

//NOTE intervals are depricated for now 
#define DEFAULT_INTERVAL 0 

typedef std::unordered_map<std::thread::id, std::vector<std::string>> thread_id_map; 
typedef std::unordered_map<std::string, std::unordered_set<taint_node_t*>> string_node_map; 

/*
 * This class is responsible for dumping to json at specific time intervals 
 * Currently depricated 
 */
class taintIntervalManager {
	public: 
		taintIntervalManager(); 

	private: 
		clock_t prev_time; 
		clock_t curr_time; 
		double interval_time; 
};

/*
 * This class is responsible for converting vectors to output (json or raw) 
 */
class taintOutputManager {
	public:
		taintOutputManager(char * outfile, bool dump_raw_taint_info); 
		taintOutputManager(bool dump_raw_taint_info); 
		taintOutputManager(char * outfile); 
		taintOutputManager(); 
		void setOutputFile(char * outfile);
		void setDumpRaw(bool dump_raw);
	private:
		std::string outfile; 
		bool dump_raw_taint_info;
	 	json output_json; 	
};

/*
 * This class will create and call methods in taintOutputManager and taintIntervalManager
 */
class taintLogManager {
	public:
		taintInfoManager(char * outfile); 
		taintInfoManager(); 
		taintInfoManager~(); 
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
		taintIntervalManager * interval_manager; 
};

/*
 * Create labels and union labels together 
 */
class taintPropagationManager {
	public: 
		taintPropagationManager(char * shad_mem_ptr, char * taint_forest_ptr); 
		taintPropagationManager~();
	 	dfsan_label createNewLabel(dfsan_label offset, taint_source_id taint_id); 
		dfsan_label createUnionLabel(dfsan_label l1, dfsan_label l2); 	
	private:
	 	std::unordered_map<dfsan_label, std::unordered_map<dfsan_label, dfsan_label>> union_table; 	
		decay_val taint_node_ttl;
		std::mutex taint_prop_lock;
		char * shadow_mem;
		char * taint_forest; 	

};

#endif 

