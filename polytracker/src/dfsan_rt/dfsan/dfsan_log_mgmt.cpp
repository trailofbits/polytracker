#include <iostream>
#include <fstream>
#include <set>
#include <stack>
#include "sanitizer_common/sanitizer_atomic.h"
#include "sanitizer_common/sanitizer_common.h"
#include "sanitizer_common/sanitizer_file.h"
#include "sanitizer_common/sanitizer_flags.h"
#include "sanitizer_common/sanitizer_flag_parser.h"
#include "sanitizer_common/sanitizer_libc.h"
#include "dfsan/dfsan_log_mgmt.h"
#include "dfsan/taint_management.hpp"

using namespace __dfsan; 

//MAPPING MANAGER
taintMappingManager::taintMappingManager(char * shad_mem_ptr, char * forest_ptr) {
	shad_mem = shad_mem_ptr; 
	forest_mem = forest_ptr; 
}

taintMappingManager::~taintMappingManager() {} 

//NOTE we might not need locks here, but just for now im adding them 
taint_node_t *
taintMappingManager::getTaintNode(dfsan_label label) {
	taint_mapping_lock.lock(); 
	taint_node_t * ret_node = (taint_node_t*)(forest_mem + (label * sizeof(taint_node_t)));
	taint_mapping_lock.unlock(); 
	return ret_node; 
}

dfsan_label 
taintMappingManager::getTaintLabel(taint_node_t * node) {
	taint_mapping_lock.lock(); 
	dfsan_label ret_label = ((char*)node - forest_mem)/sizeof(taint_node_t);
	taint_mapping_lock.unlock();
	return ret_label; 
}	


void 
taintManager::logCompare(dfsan_label some_label) {
	if (some_label == 0) {return;}
	taint_prop_lock.lock();
	taint_node_t * curr_node = getTaintNode(some_label);
	std::thread::id this_id = std::this_thread::get_id(); 
	std::vector<std::string> func_stack = thread_stack_map[this_id];
	(function_to_cmp_bytes)[func_stack[func_stack.size()-1]].insert(curr_node);
	(function_to_bytes)[func_stack[func_stack.size()-1]].insert(curr_node);	      
	taint_prop_lock.unlock();
}

void 
taintManager::logOperation(dfsan_label some_label) {
	if (some_label == 0) {return;}
	taint_prop_lock.lock();
	taint_node_t * new_node = getTaintNode(some_label);
	std::thread::id this_id = std::this_thread::get_id();
	std::vector<std::string> func_stack = thread_stack_map[this_id];
	(function_to_bytes)[func_stack[func_stack.size()-1]].insert(new_node);
	taint_prop_lock.unlock();
}

int
taintManager::logFunctionEntry(char * fname) {
	taint_prop_lock.lock();
	std::string func_name = std::string(fname); 
	std::string new_str = std::string(fname);
	std::thread::id this_id = std::this_thread::get_id();
	if (thread_stack_map[this_id].size() > 0) {
		std::string caller = (thread_stack_map)[this_id].back();
		(runtime_cfg)[new_str].insert(caller);
	}
	else {
		//This indicates the cfg entrypoint 
		std::string caller = "";
		(runtime_cfg)[new_str].insert(caller);
	}
	(thread_stack_map)[this_id].push_back(new_str);
	taint_prop_lock.unlock();
	return thread_stack_map[this_id].size()-1;
}

void
taintManager::logFunctionExit() {
	taint_prop_lock.lock();
	std::thread::id this_id = std::this_thread::get_id();
	(thread_stack_map)[this_id].pop_back();
	taint_prop_lock.unlock();
}

void 
taintManager::resetFrame(int * index) {
	taint_prop_lock.lock();
	if (index == nullptr) {
		std::cout << "Pointer to array index is null! Instrumentation error, aborting!" << std::endl; 
		abort(); 
	}
	std::thread::id this_id = std::this_thread::get_id(); 
	//NOTE this could use some testing 
	//Get the function before we reset the frame (should be the one that called longjmp) 
	std::string caller_func = thread_stack_map[this_id].back();
	//Reset the frame 	
	thread_stack_map[this_id].resize(*index + 1); 
	//Get the current function 
	std::string curr_func = thread_stack_map[this_id].back(); 
	//Insert the function that called longjmp in cfg 
	runtime_cfg[curr_func].insert(caller_func); 
	taint_prop_lock.unlock();
}

void 
taintManager::addJsonVersion() {
	output_json["version"] = POLYTRACKER_VERSION; 
}

void 
taintManager::addJsonRuntimeCFG() {
	std::unordered_map<std::string, std::unordered_set<std::string>>::iterator cfg_it;
	for (cfg_it = runtime_cfg.begin(); cfg_it != runtime_cfg.end(); cfg_it++) {
		json j_set(cfg_it->second);
		output_json["runtime_cfg"][cfg_it->first] = j_set;
	}
}

//TODO Document this
void
taintManager::outputRawTaintForest() {
	std::string forest_fname = outfile + "_forest.bin";
	FILE * forest_file = fopen(forest_fname.c_str(), "w");
	if (forest_file == NULL) {
		std::cout << "Failed to dump forest to file: " << forest_fname << std::endl;
		exit(1);
	}

	taint_node_t * curr = nullptr;
	for (int i = 1; i < next_label; i++) {
		curr = getTaintNode(i);
		dfsan_label node_p1 = getTaintLabel(curr->p1);
		dfsan_label node_p2 = getTaintLabel(curr->p2);
		fwrite(&(node_p1), sizeof(dfsan_label), 1, forest_file);
		fwrite(&(node_p2), sizeof(dfsan_label), 1, forest_file);
		fwrite(&(curr->decay), sizeof(curr->decay), 1, forest_file);
	}
	fclose(forest_file);
}

void
taintManager::addTaintSources() {
	auto name_target_map = getTargets();
	for (auto it = name_target_map.begin(); it != name_target_map.end(); it++) {
		targetInfo * targ_info = it->second;
		output_json["taint_sources"][it->first]["start_byte"] = targ_info->byte_start;
		output_json["taint_sources"][it->first]["end_byte"] = targ_info->byte_end;
		auto target_metadata = getMetadata(targ_info);
		if (!target_metadata.is_null()) {
			output_json["taint_sources"][it->first]["metadata"] = target_metadata;
		}
	}
}

void
taintManager::addCanonicalMapping() {
	for (auto it = canonical_mapping.begin(); it != canonical_mapping.end(); it++) {
		output_json["canonical_mapping"][it->first] = it->second;
	}
}

void taintManager::addTaintedBlocks() {
	json tainted_chunks(taint_bytes_processed);
	output_json["tainted_input_blocks"] = tainted_chunks;
}

void
taintManager::outputRawTaintSets() {
	string_node_map::iterator it;

	addJsonVersion();
	addJsonRuntimeCFG();
	addTaintSources();
	addCanonicalMapping();
	addTaintedBlocks();

	for (it = function_to_bytes.begin(); it != function_to_bytes.end(); it++) {
		auto set = it->second;
		std::set<dfsan_label> label_set;
		for (auto it = set.begin(); it != set.end(); it++) {
			label_set.insert(getTaintLabel(*it));
		}
		json byte_set(label_set);
		output_json["tainted_functions"][it->first]["input_bytes"] = byte_set;
		if (function_to_cmp_bytes.find(it->first) != function_to_cmp_bytes.end()) {
			auto cmp_set = it->second;
			std::set<dfsan_label> cmp_label_set;
			for (auto it = cmp_set.begin(); it != cmp_set.end(); it++) {
				cmp_label_set.insert(getTaintLabel(*it));
			}
		}
	}
	std::string output_string = outfile + "_process_set.json";
	std::ofstream o(output_string);
	o << std::setw(4) << output_json;
	o.close();
}

void
taintManager::output() {
	taint_prop_lock.lock();
	//TODO Output header with settings for POLYSTART and POLYEND etc etc
	//This allows us to interpret the forest properly
	//TODO output taint source mappings (not needed right now)
	//TODO maybe even prefix the node mappings with the "current" node
	//That allows us to process it when doing
	outputRawTaintForest();
	outputRawTaintSets();
	taint_prop_lock.unlock();
}

//PROPAGATION MANAGER
taintManager::taintManager(decay_val init_decay, char* shad_mem,
		char* forest_ptr) : taintMappingManager(shad_mem, forest_ptr), taint_node_ttl(init_decay) {
	next_label = 1;
}

taintManager::~taintManager() {}

dfsan_label
taintManager::createReturnLabel(int file_byte_offset) {
	taint_prop_lock.lock();
	dfsan_label ret_label = createCanonicalLabel(file_byte_offset);
	taint_prop_lock.unlock();
	return ret_label;
}

dfsan_label 
taintManager::createCanonicalLabel(int file_byte_offset) {
	dfsan_label new_label = next_label;
	checkMaxLabel(new_label);
	taint_node_t * new_node = getTaintNode(new_label);
	new_node->p1 = NULL; 
	new_node->p2 = NULL; 
	new_node->decay = taint_node_ttl; 
	canonical_mapping[new_label] = file_byte_offset;
	return new_label; 
}

bool taintManager::taintData(int fd, char * mem, int offset, int len) {
	taint_prop_lock.lock();
	if (!isTracking(fd)) {
		taint_prop_lock.unlock();
		return false;
	}
	targetInfo * targ_info = getTargetInfo(fd);
	taintTargetRange(mem, offset, len, targ_info->byte_start, targ_info->byte_end);
	taint_prop_lock.unlock();
	return true;
}

bool taintManager::taintData(FILE * fd, char * mem, int offset, int len) {
	taint_prop_lock.lock();
	if (!isTracking(fd)) {
		taint_prop_lock.unlock();
		return false;
	}
	targetInfo * targ_info = getTargetInfo(fd);
	taintTargetRange(mem, offset, len, targ_info->byte_start, targ_info->byte_end);
	taint_prop_lock.unlock();
	return true;
}
/*
 * This function is responsible for marking memory locations as tainted, and is called when taint is processed
 * by functions like read, pread, mmap, recv, etc.
 *
 * Mem is a pointer to the data we want to taint
 * Offset tells us at what point in the stream/file we are in (before we read)
 * Len tells us how much we just read in
 * byte_start and byte_end are target specific options that allow us to only taint specific regions
 * like (0-100) etc etc
 *
 * If a byte is supposed to be tainted we make a new taint label for it, these labels are assigned sequentially.
 *
 * Then, we keep track of what canonical labels map to what original file offsets.
 *
 * Then we update the shadow memory region with the new label
 */
void taintManager::taintTargetRange(char * mem, int offset, int len, int byte_start, int byte_end) {
	int curr_byte_num = offset;
	int taint_offset_start = -1, taint_offset_end = -1;
	for (char * curr_byte = (char*)mem; curr_byte_num < offset + len;
			curr_byte_num++, curr_byte++)
	{
		//If byte end is < 0, then we don't care about ranges.
		if (byte_end < 0 ||
				(curr_byte_num >= byte_start && curr_byte_num <= byte_end)) {
			/*
			 * Thoughts: When creating the canonical label we need to pass the byte
			 * it over to the taintProp manager
			 * Because during runtime we also create some more canonical bytes, which goes back into the prop
			 * manager, and because it misses the infomanager it means that we don't store it in the canonical
			 * label mapping REEEEEEEEEE
			 */
			dfsan_label new_label = createCanonicalLabel(curr_byte_num);
			dfsan_set_label(new_label, curr_byte, TAINT_GRANULARITY);
			canonical_mapping[new_label] = curr_byte_num;
			if (taint_offset_start == -1) {
				taint_offset_start = curr_byte_num;
				taint_offset_end = curr_byte_num;
			}
			else if (curr_byte_num > taint_offset_end) {
				taint_offset_end = curr_byte_num;
			}
		}
	}
	taint_bytes_processed.push_back(std::pair<int, int>(taint_offset_start, taint_offset_end));
}

dfsan_label
taintManager::_unionLabel(dfsan_label l1, dfsan_label l2, decay_val init_decay) {
	dfsan_label ret_label = next_label + 1;
	next_label++;
	checkMaxLabel(ret_label);
	taint_node_t * new_node = getTaintNode(ret_label);
	new_node->p1 = getTaintNode(l1);
	new_node->p2 = getTaintNode(l2);
	new_node->decay = init_decay; 
	return ret_label; 
}

dfsan_label 
taintManager::createUnionLabel(dfsan_label l1, dfsan_label l2) {
	taint_prop_lock.lock(); 
	//If sanitizer debug is on, this checks that l1 != l2
	DCHECK_NE(l1, l2);
	if (l1 == 0) {
		taint_prop_lock.unlock(); 
		return l2;
	}
	if (l2 == 0) {
		taint_prop_lock.unlock(); 
		return l1;
	}
	if (l1 > l2) {
		Swap(l1, l2);
	}
	//Quick union table check
	if ((union_table[l1]).find(l2) != (union_table[l1]).end()) {
		auto val = union_table[l1].find(l2);
		taint_prop_lock.unlock(); 
		return val->second;
	}
	//Check for max decay
	taint_node_t * p1 = getTaintNode(l1);
	taint_node_t * p2 = getTaintNode(l2);
	//This calculates the average of the two decays, and then decreases it by a factor of 2.
	decay_val max_decay = (p1->decay + p2->decay) / 4;
	if (max_decay == 0) {
		taint_prop_lock.unlock(); 
		return 0;
	}
	dfsan_label label = _unionLabel(l1, l2, max_decay);
	(union_table[l1])[l2] = label;	
	taint_prop_lock.unlock(); 
	return label;
}

void 
taintManager::checkMaxLabel(dfsan_label label) {
	if (label == MAX_LABELS) {
		std::cout << "ERROR: MAX LABEL REACHED, ABORTING!" << std::endl;
		//Cant exit due to our exit handlers 
		abort();  	
	}
}

dfsan_label 
taintManager::getLastLabel() {
	taint_prop_lock.lock();
	dfsan_label last_label = next_label;
	taint_prop_lock.unlock();
	return last_label;
}
