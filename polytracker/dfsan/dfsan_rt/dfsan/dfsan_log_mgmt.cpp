#include <iostream>
#include <fstream>
#include <stack>
#include "../sanitizer_common/sanitizer_atomic.h"
#include "../sanitizer_common/sanitizer_common.h"
#include "../sanitizer_common/sanitizer_file.h"
#include "../sanitizer_common/sanitizer_flags.h"
#include "../sanitizer_common/sanitizer_flag_parser.h"
#include "../sanitizer_common/sanitizer_libc.h"
#include "dfsan_log_mgmt.h"

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

//LOG MANAGER
taintLogManager::taintLogManager(taintMappingManager * map_mgr, taintInfoManager * info_mgr, 
		std::string of, bool should_dump) {
	outfile = of; 
	dump_raw_taint_info = should_dump; 
	map_manager = map_mgr;
 	info_manager = info_mgr;	
}

taintLogManager::~taintLogManager() {}

void 
taintLogManager::logCompare(dfsan_label some_label) {
	if (some_label == 0) {return;}
	taint_log_lock.lock();
	taint_node_t * curr_node = map_manager->getTaintNode(some_label); 
	std::thread::id this_id = std::this_thread::get_id(); 
	std::vector<std::string> func_stack = thread_stack_map[this_id];
	(function_to_cmp_bytes)[func_stack[func_stack.size()-1]].insert(curr_node);
	(function_to_bytes)[func_stack[func_stack.size()-1]].insert(curr_node);	      
	taint_log_lock.unlock(); 
}

void 
taintLogManager::logOperation(dfsan_label some_label) {
	if (some_label == 0) {return;}
	taint_log_lock.lock();
	taint_node_t * new_node = map_manager->getTaintNode(some_label);
	std::thread::id this_id = std::this_thread::get_id();
	std::vector<std::string> func_stack = thread_stack_map[this_id];
	(function_to_bytes)[func_stack[func_stack.size()-1]].insert(new_node);
	taint_log_lock.unlock(); 
}

int
taintLogManager::logFunctionEntry(char * fname) {
	taint_log_lock.lock();
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
	taint_log_lock.unlock();
	return thread_stack_map[this_id].size()-1;
}

void
taintLogManager::logFunctionExit() {
	taint_log_lock.lock();
	std::thread::id this_id = std::this_thread::get_id();
	(thread_stack_map)[this_id].pop_back();
	taint_log_lock.unlock();
}

void 
taintLogManager::resetFrame(int * index) {
	taint_log_lock.lock(); 
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
	taint_log_lock.unlock(); 
}

void 
taintLogManager::addJsonVersion() {
	output_json["version"] = POLYTRACKER_VERSION; 
}

void 
taintLogManager::addJsonRuntimeCFG() {
	std::unordered_map<std::string, std::unordered_set<std::string>>::iterator cfg_it;
	for (cfg_it = runtime_cfg.begin(); cfg_it != runtime_cfg.end(); cfg_it++) {
		json j_set(cfg_it->second);
		output_json["runtime_cfg"][cfg_it->first] = j_set;
	}
}

std::unordered_map<std::string, std::set<dfsan_label>>
taintLogManager::utilityPartitionSet(Roaring label_set) {
	std::unordered_map<std::string, std::set<dfsan_label>> source_set_map;
	for (auto it = label_set.begin(); it != label_set.end(); it++) {
		taint_node_t * curr_node = map_manager->getTaintNode(*it); 
		std::string source_name = info_manager->getTaintSource(curr_node->taint_source); 
		source_set_map[source_name].insert(*it); 
	}	
	return source_set_map;	
}

Roaring
taintLogManager::iterativeDFS(taint_node_t * node) {
	//Stack instead of using call stack 
	std::stack<taint_node_t *> * node_stack = new std::stack<taint_node_t*>(); 
	//Collection of parent labels for the node we want to return 
	Roaring parent_labels;
	std::vector<bool> * visited_node = new std::vector<bool>(max_label + 1, false); 
	node_stack->push(node); 
	//Go until we have no more paths to explore 
	while (!node_stack->empty()) {
		taint_node_t * curr_node = node_stack->top();
		node_stack->pop(); 

		dfsan_label curr_label = map_manager->getTaintLabel(curr_node); 
		//If visited just continue
		if ((*visited_node)[curr_label])  {
			continue; 
		}
		//Visited for first time 
		(*visited_node)[curr_label] = true;
		
		//If we hit a canonical label, we done
		if (curr_node->p1 == NULL && curr_node->p2 == NULL) {
			parent_labels.add(curr_label); 
			continue; 
		}
		//Else if we havent checked out the parents, lets do it
		if (curr_node->p1 != NULL) {
			dfsan_label p1_label = map_manager->getTaintLabel(curr_node->p1); 
		 	if ((*visited_node)[p1_label] == false) {
				node_stack->push(curr_node->p1); 
			}	
		}
		if (curr_node->p2 != NULL) {
			dfsan_label p2_label = map_manager->getTaintLabel(curr_node->p2); 
			if ((*visited_node)[p2_label] == false) {
				node_stack->push(curr_node->p2);
			}
		}	
	}
	delete visited_node; 
	delete node_stack; 
	return parent_labels; 
}

Roaring
taintLogManager::processAll(std::unordered_set<taint_node_t *> * nodes) {
	Roaring all_labels; 

	for (auto it = nodes->begin(); it != nodes->end(); it++) {
		Roaring ret = iterativeDFS(*it);
		//You can bitwise or on the roaring sets 
		all_labels = all_labels | ret; 	
	}
	return all_labels; 
}

/*
 * Map from func_names --> set<nodes> 
 * Turn func_names --> Roaring
 * Now split the set of labels based on their origin 
 * So Roaring --> map<source, dfsan_label set> 
 * 	put json object in json
 *
 * Repeat for compare bytes. 
 */
void 
taintLogManager::addJsonBytesMappings() {
	string_node_map::iterator it; 

	//NOTE This could be improved later by having a single mapping from name --> pair<all_set, cmp_set>
	//Instead of 2 maps 
	for (it = function_to_bytes.begin(); it != function_to_bytes.end(); it++) {
		//We convert to Roaring to save space during this traversal/caching 
		Roaring labels = processAll(&it->second);
		//Split up roaring based on origin bytes, and then into sets which we can make jsons 
		std::unordered_map<std::string, std::set<dfsan_label>> source_set_map  = utilityPartitionSet(labels);
		for (auto map_it = source_set_map.begin(); map_it != source_set_map.end(); map_it++) {
			json byte_set(map_it->second); 
			std::string source_name = "POLYTRACKER " + map_it->first; 
			output_json["tainted_functions"][it->first]["input_bytes"][source_name] = byte_set; 
		}
	}
	for (it = function_to_cmp_bytes.begin(); it != function_to_cmp_bytes.end(); it++) {
		//We convert to Roaring to save space during this traversal/caching 
		Roaring labels = processAll(&it->second);
		//Split up roaring based on origin bytes, and then into sets which we can make jsons 
		std::unordered_map<std::string, std::set<dfsan_label>> source_set_map  = utilityPartitionSet(labels);
		for (auto map_it = source_set_map.begin(); map_it != source_set_map.end(); map_it++) {
			json byte_set(map_it->second); 
			std::string source_name = "POLYTRACKER " + map_it->first; 
			output_json["tainted_functions"][it->first]["cmp_bytes"][source_name] = byte_set; 
		}
	}
}

void 
taintLogManager::writeJson() {
	std::ofstream o(outfile); 
	o << std::setw(4) << output_json << std::endl; 
	o.close(); 
}

void
taintLogManager::outputJson() {
	addJsonVersion(); 
	addJsonRuntimeCFG(); 	
	addJsonBytesMappings();
	writeJson(); 
}

void
taintLogManager::outputRawTaintForest(dfsan_label max_label) {
	std::string forest_fname = outfile + "_forest.bin";
	FILE * forest_file = fopen(forest_fname.c_str(), "w");
	if (forest_file == NULL) {
		std::cout << "Failed to dump forest to file: " << forest_fname << std::endl;
		exit(1);
	}
	taint_node_t * curr = nullptr;
	for (int i = 0; i < max_label; i++) {
		curr = map_manager->getTaintNode(i);
		dfsan_label node_p1 = map_manager->getTaintLabel(curr->p1);
		dfsan_label node_p2 = map_manager->getTaintLabel(curr->p2);
		fwrite(&(node_p1), sizeof(dfsan_label), 1, forest_file);
		fwrite(&(node_p2), sizeof(dfsan_label), 1, forest_file);
		fwrite(&(curr->taint_source), sizeof(curr->taint_source), 1, forest_file);
		fwrite(&(curr->decay), sizeof(curr->decay), 1, forest_file);
	}
	fclose(forest_file);	
}

void
taintLogManager::outputRawTaintSets() {
	std::unordered_map<std::string, std::unordered_set<taint_node_t*>>::iterator it;

	addJsonVersion();
 	addJsonRuntimeCFG();

	//Collect bytes without doing any post order traversal/source mapping  
	for (it = function_to_bytes.begin(); it != function_to_bytes.end(); it++) {
		std::unordered_set<dfsan_label> large_set;
		std::unordered_set<taint_node_t*> ptr_set;
		ptr_set = it->second;
		for (auto ptr_it = ptr_set.begin(); ptr_it != ptr_set.end(); ptr_it++) {
			large_set.insert(map_manager->getTaintLabel(*ptr_it));
		}
		json j_set(large_set);
		output_json[it->first] = j_set;
	}
	std::string output_string = outfile + "_process_set.json";
	std::ofstream o(output_string);
	o << std::setw(4) << output_json;
	o.close();
}

void
taintLogManager::output(dfsan_label max) {
	taint_log_lock.lock();
	max_label = max;
	if (dump_raw_taint_info) {
		outputRawTaintForest(max_label); 
		outputRawTaintSets();
		taint_log_lock.unlock(); 
		return; 
	}
	outputJson();
	taint_log_lock.unlock(); 	
}

//PROPAGATION MANAGER
taintPropagationManager::taintPropagationManager(taintMappingManager * map_mgr, 
		decay_val init_decay_val, dfsan_label start_union_label) {
	taint_node_ttl = init_decay_val; 
	map_manager = map_mgr; 
	shadow_union_label = start_union_label; 
}

taintPropagationManager::~taintPropagationManager() {} 

dfsan_label 
taintPropagationManager::createNewLabel(dfsan_label offset, taint_source_id taint_id) {
	taint_prop_lock.lock(); 
	dfsan_label new_label = offset + 1; 

	_checkMaxLabel(new_label);

	taint_node_t * new_node = map_manager->getTaintNode(new_label); 
	new_node->p1 = NULL; 
	new_node->p2 = NULL; 
	new_node->taint_source = taint_id; 
	new_node->decay = taint_node_ttl; 
	taint_prop_lock.unlock(); 
	return new_label; 
}	

dfsan_label
taintPropagationManager::_createUnionLabel(dfsan_label l1, dfsan_label l2, decay_val init_decay) {
	dfsan_label ret_label = shadow_union_label + 1;
	shadow_union_label++;
	
	_checkMaxLabel(ret_label); 

	taint_node_t * new_node = map_manager->getTaintNode(ret_label); 
	new_node->p1 = map_manager->getTaintNode(l1); 
	new_node->p2 = map_manager->getTaintNode(l2); 
	new_node->decay = init_decay; 
	new_node->taint_source = new_node->p1->taint_source | new_node->p2->taint_source;
	return ret_label; 
}

dfsan_label 
taintPropagationManager::unionLabels(dfsan_label l1, dfsan_label l2) {
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
	taint_node_t * p1 = map_manager->getTaintNode(l1);
	taint_node_t * p2 = map_manager->getTaintNode(l2);
	//This calculates the average of the two decays, and then decreases it by a factor of 2.
	decay_val max_decay = (p1->decay + p2->decay) / 4;
	if (max_decay == 0) {
		taint_prop_lock.unlock(); 
		return 0;
	}
	dfsan_label label = _createUnionLabel(l1, l2, max_decay);
	(union_table[l1])[l2] = label;	
	taint_prop_lock.unlock(); 
	return label;
}

void 
taintPropagationManager::_checkMaxLabel(dfsan_label label) {
	if (label == MAX_LABELS) {
		std::cout << "ERROR: MAX LABEL REACHED, ABORTING!" << std::endl;
		//Cant exit due to our exit handlers 
		abort();  	
	}
}

dfsan_label 
taintPropagationManager::getMaxLabel() {
	taint_prop_lock.lock();
	dfsan_label max_label = shadow_union_label;
		taint_prop_lock.unlock(); 
	return max_label; 	
}
