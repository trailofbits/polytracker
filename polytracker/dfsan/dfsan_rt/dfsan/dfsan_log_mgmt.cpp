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
	dfsan_label ret_label = ((((char*)node) - forest_mem)/sizeof(taint_node_t));
	taint_mapping_lock.unlock();
	return ret_label; 
}	


//PROPAGATION MANAGER
taintPropagationManager::taintPropagationManager(taintMappingManager * map_mgr, decay_val init_decay_val, dfsan_label start_union_label) {
	taint_node_ttl = init_decay_val; 
	map_manager = map_mgr; 
	atomic_store(&next_union_label, start_union_label, memory_order_release); 
}

taintPropagationManager::~taintPropagationManager() {} 

dfsan_label 
taintPropagationManager::createNewLabel(dfsan_label offset, taint_source_id taint_id) {
	taint_prop_lock.lock(); 
	dfsan_label new_label = offset + 1; 

	_checkMaxLabel(new_label);

	taint_node_t * new_node = map_manager->getTaintNode(new_label); 
	new_node->p1 = new_node->p2 = NULL; 
	new_node->taint_source = taint_id; 
	new_node->decay = taint_node_ttl; 
	taint_prop_lock.unlock(); 
	return new_label; 
}	

dfsan_label 
taintPropagationManager::_createUnionLabel(dfsan_label l1, dfsan_label l2, decay_val init_decay) {
#ifdef DEBUG_INFO
	std::cout << "Current union label is " << next_union_label << std::endl;  
#endif	
	dfsan_label ret_label = atomic_fetch_add(&next_union_label, 1, memory_order_relaxed);
#ifdef DEBUG_INFO 
	std::cout << "Ret'd union label is " << ret_label << std::endl; 
#endif	
	_checkMaxLabel(ret_label); 

	taint_node_t * new_node = map_manager->getTaintNode(ret_label); 
	new_node->p1 = map_manager->getTaintNode(l1); 
	new_node->p2 = map_manager->getTaintNode(l2); 
	new_node->decay = init_decay; 
	new_node->taint_source = '\0';
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


