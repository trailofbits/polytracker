#include <string>
#include <vector> 
#include <iostream>
//TODO remove unused headers
#include <utility>
#include <unordered_map>
#include "dfsan/taint_management.hpp" 
#include "dfsan/dfsan_interface.h"

targetInfo::targetInfo(std::string name,
		int start, 
		int  end) {
	target_name = name;
	byte_start = start; 
	byte_end = end; 
	is_open = false;
}

targetInfo::~targetInfo() {}


taintInfoManager::taintInfoManager() {}

taintInfoManager::~taintInfoManager() {}


void taintInfoManager::createNewTargetInfo(std::string fname, int start, int end) {
	taint_info_mutex.lock();
	targetInfo * target_info = new targetInfo(fname, start, end);
	name_target_map[fname] = target_info;
	taint_info_mutex.unlock();
}	


void taintInfoManager::createNewTaintInfo(int fd, targetInfo *targ_info) {
	taint_info_mutex.lock();
	fd_target_map[fd] = targ_info;
	taint_info_mutex.unlock();
}

void taintInfoManager::createNewTaintInfo(FILE * ffd, targetInfo *targ_info) {
	taint_info_mutex.lock();
	file_target_map[ffd] = targ_info;
	taint_info_mutex.unlock();
}


bool taintInfoManager::taintData(int fd, char * mem, int offset, int len) {
	taint_info_mutex.lock();
	if (!isTracking(fd)) {
		taint_info_mutex.unlock();
		return false;
	}
	targetInfo * targ_info = fd_target_map[fd];
	taintTargetRange(mem, offset, len, targ_info->byte_start, targ_info->byte_end);
	taint_info_mutex.unlock();
	return true;
}

bool taintInfoManager::taintData(FILE * fd, char * mem, int offset, int len) {
	taint_info_mutex.lock();
	if (!isTracking(fd)) {
		taint_info_mutex.unlock();
		return false;
	}
	targetInfo * targ_info = file_target_map[fd];
	taintTargetRange(mem, offset, len, targ_info->byte_start, targ_info->byte_end);
	taint_info_mutex.unlock();
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
void taintInfoManager::taintTargetRange(char * mem, int offset, int len, int byte_start, int byte_end) {
	int curr_byte_num = offset;
	int taint_size_processed = 0;
	for (char * curr_byte = (char*)mem; curr_byte_num < offset + len;
			curr_byte_num++, curr_byte++)
	{
		//If byte end is < 0, then we don't care about ranges.
		if (byte_end < 0 ||
				(curr_byte_num >= byte_start && curr_byte_num <= byte_end)) {
			dfsan_label new_label = dfsan_create_canonical_label();
			dfsan_set_label(new_label, curr_byte, TAINT_GRANULARITY);
			canonical_mapping[new_label] = curr_byte_num;
			taint_size_processed++;
		}
	}
}
